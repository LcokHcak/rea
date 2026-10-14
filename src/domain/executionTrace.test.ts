import { expect, it } from "vitest";

import {
  executionTraceActionSchema,
  executionTraceBatchSchema,
  executionTraceEventSchema,
} from "./executionTrace.js";

it("represents an unclassified Windows provider event without inventing a function call", () => {
  const event = {
    schema_version: 1,
    source: {
      provider: "windows-eventlistener-lab",
      session_id: "controlled-1",
      stream_id: "REA-Controlled-Listener-Fixture",
      retained_index: 0,
      sequence: null,
    },
    time: { clock: "unix-epoch-ms", value: "1791873905549" },
    process: { pid: 32720, tid: null },
    event: {
      kind: "provider-event",
      phase: "instant",
      name: "REA-Controlled-Listener-Fixture/Step",
      attributes: { label: "branch-App" },
    },
  };

  expect(executionTraceEventSchema.safeParse(event).success).toBe(true);
  expect(
    executionTraceEventSchema.safeParse({
      ...event,
      event: { ...event.event, kind: "function" },
    }).success,
  ).toBe(false);
});

it("accepts earlier local v1 batches with no producer omission report", () => {
  expect(
    executionTraceBatchSchema.safeParse({
      schema_version: 1,
      events: [],
      provenance: {
        raw_record_kind: "eventlistener-callback",
        process_id: "fixture-process",
        thread_id: "unavailable",
        timestamp: "listener-callback",
        sequence: "unavailable",
        attributes: "fixture-payload",
      },
      coverage: {
        retained_records: 0,
        candidate_records: 0,
        rejected_records: 0,
        omitted_events: 0,
        records_truncated: false,
        producer_lost_events: null,
      },
    }).success,
  ).toBe(true);
});

it("keeps reader filtering distinct from producer filtering and rejects negative counts", () => {
  const batch = {
    schema_version: 1,
    events: [],
    provenance: {
      raw_record_kind: "offline ETW EVENT_RECORD",
      process_id: "ETW header",
      thread_id: "ETW header",
      timestamp: "FILETIME",
      sequence: "unavailable",
      attributes: "fixture payload",
    },
    coverage: {
      retained_records: 3,
      candidate_records: 3,
      rejected_records: 0,
      omitted_events: 0,
      records_truncated: false,
      reader_filtered_records: 2,
      producer_filtered_events: null,
      producer_lost_events: null,
    },
  };
  expect(executionTraceBatchSchema.safeParse(batch).success).toBe(true);
  expect(
    executionTraceBatchSchema.safeParse({
      ...batch,
      coverage: { ...batch.coverage, reader_filtered_records: -1 },
    }).success,
  ).toBe(false);
});

it("requires retained indexes and record counts to refer to the retained raw array", () => {
  const batch = {
    schema_version: 1,
    events: [
      {
        schema_version: 1,
        source: {
          provider: "frida",
          session_id: "selected-1",
          stream_id: "agent-1",
          retained_index: 0,
          sequence: "1",
        },
        time: null,
        process: { pid: 42, tid: 43 },
        event: { kind: "function", phase: "enter", name: "owned_fixture" },
      },
    ],
    provenance: {
      raw_record_kind: "frida-message",
      process_id: "frida-session",
      thread_id: "agent-payload",
      timestamp: "agent-payload",
      sequence: "agent-payload",
      attributes: "agent-payload",
    },
    coverage: {
      retained_records: 1,
      candidate_records: 1,
      rejected_records: 0,
      omitted_events: 0,
      records_truncated: false,
      producer_lost_events: null,
    },
  };
  expect(executionTraceBatchSchema.safeParse(batch).success).toBe(true);
  const firstEvent = batch.events[0];
  if (firstEvent === undefined) throw new Error("Expected one fixture event");
  expect(
    executionTraceBatchSchema.safeParse({
      ...batch,
      events: [
        { ...firstEvent, source: { ...firstEvent.source, retained_index: 1 } },
      ],
    }).success,
  ).toBe(false);
  expect(
    executionTraceBatchSchema.safeParse({
      ...batch,
      coverage: { ...batch.coverage, candidate_records: 2 },
    }).success,
  ).toBe(false);
  expect(
    executionTraceBatchSchema.safeParse({
      ...batch,
      coverage: { ...batch.coverage, rejected_records: 2 },
    }).success,
  ).toBe(false);
});

it("preserves exact ETW FILETIME ticks as a distinct clock domain", () => {
  const parsed = executionTraceEventSchema.safeParse({
    schema_version: 1,
    source: {
      provider: "windows-etw-private-lab",
      session_id: "controlled-private-etw-v3",
      stream_id: "10f56ba3-2600-598c-df02-e43d836ea564",
      retained_index: 2,
      sequence: null,
    },
    time: { clock: "windows-filetime-100ns", value: "134363768213715202" },
    process: { pid: 44288, tid: 44600 },
    event: {
      kind: "provider-event",
      phase: "instant",
      name: "REA-Controlled-Private-ETW/EventWriteString",
      attributes: { label: "enter" },
    },
  });
  expect(parsed.success).toBe(true);
});

it("represents an observed basic block with exact pointer strings", () => {
  const base = {
    schema_version: 1,
    source: {
      provider: "frida",
      session_id: "controlled-branch",
      stream_id: "stalker-agent",
      retained_index: 0,
      sequence: "1",
    },
    time: null,
    process: { pid: 42, tid: 42 },
    event: {
      kind: "basic-block",
      phase: "execute",
      start_address: "0x7ff99441f3d7",
      end_address: "0x7ff99441f3e1",
      attributes: { "block.start_offset": "0x5" },
    },
  };

  expect(executionTraceEventSchema.safeParse(base).success).toBe(true);
  for (const startAddress of [
    42,
    "7ff99441f3d7",
    "0xxyz",
    "0x" + "a".repeat(17),
  ]) {
    expect(
      executionTraceEventSchema.safeParse({
        ...base,
        event: { ...base.event, start_address: startAddress },
      }).success,
    ).toBe(false);
  }
});

it("associates a basic block with a producer-observed invocation", () => {
  const block = {
    kind: "basic-block",
    phase: "execute",
    start_address: "0x7ff99441f3d7",
    end_address: "0x7ff99441f3e1",
    call: { id: "3", parent_id: null },
  };
  expect(executionTraceActionSchema.safeParse(block).success).toBe(true);
  expect(
    executionTraceActionSchema.safeParse({
      ...block,
      call: { id: "03", parent_id: null },
    }).success,
  ).toBe(false);
});
