import { z } from "zod";

import {
  executionTraceActionSchema,
  executionTraceIntegerSchema,
  executionTraceTimeSchema,
  type ExecutionTraceBatch,
  type ExecutionTraceEvent,
} from "../domain/executionTrace.js";
import type { JsonValue } from "../domain/jsonValue.js";

const MAX_EVENTS = 10_000;
const selectedScriptIdSchema = z.string().min(1).max(256);
const agentEventSchema = z.strictObject({
  schema_version: z.literal(1),
  sequence: executionTraceIntegerSchema,
  pid: z.number().int().nonnegative(),
  tid: z.number().int().nonnegative(),
  time: executionTraceTimeSchema.nullable(),
  event: executionTraceActionSchema,
});
const agentStatusSchema = z.strictObject({
  schema_version: z.literal(1),
  pid: z.number().int().nonnegative(),
  emitted_events: z.number().int().nonnegative(),
  omitted_events: z.number().int().nonnegative(),
  filtered_events: z.number().int().nonnegative().optional(),
  producer_lost_events: z.number().int().nonnegative().nullable(),
});

const isRecord = (value: JsonValue): value is Record<string, JsonValue> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isSelectedMessage = (
  message: JsonValue,
  selectedScriptId: string | undefined,
): boolean =>
  selectedScriptId === undefined ||
  (isRecord(message) && message.script_id === selectedScriptId);

type AgentStatus = {
  readonly scriptId: string;
  readonly retainedIndex: number;
  readonly emittedEvents: number;
  readonly omittedEvents: number;
  readonly filteredEvents: number | null;
  readonly producerLostEvents: number | null;
};

const parseStatus = (
  message: Record<string, JsonValue>,
  payload: Record<string, JsonValue>,
  retainedIndex: number,
  targetPid: number,
): AgentStatus | undefined => {
  const scriptId = message.script_id;
  const parsed = agentStatusSchema.safeParse(payload.rea_trace_status);
  if (
    "rea_trace" in payload ||
    message.payload_truncated === true ||
    message.type_truncated === true ||
    typeof scriptId !== "string" ||
    scriptId.length === 0 ||
    scriptId.length > 256 ||
    !parsed.success ||
    parsed.data.pid !== targetPid
  )
    return undefined;
  return {
    scriptId,
    retainedIndex,
    emittedEvents: parsed.data.emitted_events,
    omittedEvents: parsed.data.omitted_events,
    filteredEvents: parsed.data.filtered_events ?? null,
    producerLostEvents: parsed.data.producer_lost_events,
  };
};

const parseAgentEvent = (
  message: Record<string, JsonValue>,
  payload: Record<string, JsonValue>,
  targetPid: number,
):
  | {
      readonly scriptId: string;
      readonly value: z.infer<typeof agentEventSchema>;
    }
  | undefined => {
  const scriptId = message.script_id;
  const parsed = agentEventSchema.safeParse(payload.rea_trace);
  if (
    message.payload_truncated === true ||
    message.type_truncated === true ||
    typeof scriptId !== "string" ||
    scriptId.length === 0 ||
    scriptId.length > 256 ||
    !parsed.success ||
    parsed.data.pid !== targetPid
  )
    return undefined;
  return { scriptId, value: parsed.data };
};

const reconcileStatus = (
  status: AgentStatus | undefined,
  counts: {
    readonly statusFrames: number;
    readonly rejectedRecords: number;
    readonly omittedEvents: number;
    readonly recordsTruncated: boolean;
  },
  events: readonly ExecutionTraceEvent[],
): AgentStatus | undefined => {
  if (
    counts.recordsTruncated ||
    counts.statusFrames !== 1 ||
    status === undefined ||
    counts.rejectedRecords !== 0 ||
    counts.omittedEvents !== 0 ||
    status.emittedEvents !== events.length ||
    !events.every(
      (event, index) =>
        event.source.stream_id === status.scriptId &&
        event.source.retained_index < status.retainedIndex &&
        // The opt-in v1 status counts emitted records, numbered from one.
        event.source.sequence === String(index + 1),
    )
  )
    return undefined;
  return status;
};

/**
 * Interpret only opt-in Frida agent envelopes. Raw messages remain owned by the
 * Frida session; an optional script selector preserves session-wide raw indexes.
 * This projection never treats arbitrary script logs as calls.
 */
export const normalizeFridaExecutionTrace = (
  messages: readonly JsonValue[],
  session: {
    readonly sessionId: string;
    readonly pid: number;
    readonly messagesTruncated: boolean;
    readonly selectedScriptId?: string;
  },
): ExecutionTraceBatch => {
  const selectedScriptId =
    session.selectedScriptId === undefined
      ? undefined
      : selectedScriptIdSchema.parse(session.selectedScriptId);
  const events: ExecutionTraceEvent[] = [];
  let candidateMessages = 0;
  let rejectedMessages = 0;
  let omittedEvents = 0;
  let readerFilteredRecords = 0;
  let statusFrames = 0;
  let status: AgentStatus | undefined;

  for (const [retainedIndex, message] of messages.entries()) {
    if (!isSelectedMessage(message, selectedScriptId)) {
      readerFilteredRecords += 1;
      continue;
    }
    if (!isRecord(message) || message.type !== "send") continue;
    const payload = message.payload;
    if (payload === undefined || !isRecord(payload)) continue;
    if ("rea_trace_status" in payload) {
      statusFrames += 1;
      status = parseStatus(message, payload, retainedIndex, session.pid);
    }
    if (!("rea_trace" in payload)) continue;
    candidateMessages += 1;
    const parsed = parseAgentEvent(message, payload, session.pid);
    if (parsed === undefined) {
      rejectedMessages += 1;
      continue;
    }
    if (events.length >= MAX_EVENTS) {
      omittedEvents += 1;
      continue;
    }
    events.push({
      schema_version: 1,
      source: {
        provider: "frida",
        session_id: session.sessionId,
        stream_id: parsed.scriptId,
        retained_index: retainedIndex,
        sequence: parsed.value.sequence,
      },
      time: parsed.value.time,
      process: { pid: session.pid, tid: parsed.value.tid },
      event: parsed.value.event,
    });
  }

  const finalStatus = reconcileStatus(
    status,
    {
      statusFrames,
      rejectedRecords: rejectedMessages,
      omittedEvents,
      recordsTruncated: session.messagesTruncated,
    },
    events,
  );

  return {
    schema_version: 1,
    events,
    provenance: {
      raw_record_kind: "frida-message",
      process_id: "frida-session",
      thread_id: "agent-payload",
      timestamp: "agent-payload",
      sequence: "agent-payload",
      attributes: "agent-payload",
    },
    coverage: {
      retained_records: messages.length,
      candidate_records: candidateMessages,
      rejected_records: rejectedMessages,
      omitted_events: omittedEvents,
      records_truncated: session.messagesTruncated,
      reader_filtered_records:
        selectedScriptId === undefined ? null : readerFilteredRecords,
      producer_omitted_events: finalStatus?.omittedEvents ?? null,
      producer_filtered_events: finalStatus?.filteredEvents ?? null,
      producer_lost_events: finalStatus?.producerLostEvents ?? null,
    },
  };
};
