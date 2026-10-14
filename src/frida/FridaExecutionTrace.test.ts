import { expect, it } from "vitest";

import {
  executionTraceBatchSchema,
  executionTraceEventSchema,
} from "../domain/executionTrace.js";
import { normalizeFridaExecutionTrace } from "./FridaExecutionTrace.js";

const eventPayload = (sequence: string, pid = 13213) => ({
  rea_trace: {
    schema_version: 1,
    sequence,
    pid,
    tid: 13213,
    time: { clock: "unix-epoch-ms", value: "1791867680490" },
    event: {
      kind: "function",
      phase: "enter",
      name: "io.appium.android.apis.ApiDemos.onCreate",
      attributes: { "intent.path": "App" },
    },
  },
});

it("normalizes only explicit v1 Frida events with retained-message provenance", () => {
  const trace = normalizeFridaExecutionTrace(
    [
      { script_id: "agent-1", type: "send", payload: { kind: "hook_ready" } },
      { script_id: "agent-1", type: "send", payload: eventPayload("1") },
    ],
    { sessionId: "session-1", pid: 13213, messagesTruncated: false },
  );

  expect(trace.events).toEqual([
    {
      schema_version: 1,
      source: {
        provider: "frida",
        session_id: "session-1",
        stream_id: "agent-1",
        retained_index: 1,
        sequence: "1",
      },
      time: { clock: "unix-epoch-ms", value: "1791867680490" },
      process: { pid: 13213, tid: 13213 },
      event: {
        kind: "function",
        phase: "enter",
        name: "io.appium.android.apis.ApiDemos.onCreate",
        attributes: { "intent.path": "App" },
      },
    },
  ]);
  expect(executionTraceEventSchema.safeParse(trace.events[0]).success).toBe(
    true,
  );
  expect(trace.provenance).toEqual({
    raw_record_kind: "frida-message",
    process_id: "frida-session",
    thread_id: "agent-payload",
    timestamp: "agent-payload",
    sequence: "agent-payload",
    attributes: "agent-payload",
  });
  expect(trace.coverage).toEqual({
    retained_records: 2,
    candidate_records: 1,
    rejected_records: 0,
    omitted_events: 0,
    records_truncated: false,
    reader_filtered_records: null,
    producer_omitted_events: null,
    producer_filtered_events: null,
    producer_lost_events: null,
  });
});

it("rejects malformed or mismatched producer claims without changing raw messages", () => {
  const messages = [
    { script_id: "agent-1", type: "send", payload: eventPayload("1", 99) },
    { script_id: "agent-1", type: "send", payload: eventPayload("2") },
    {
      script_id: "agent-1",
      type: "send",
      payload_truncated: true,
      payload: eventPayload("3"),
    },
  ];
  const before = JSON.stringify(messages);
  const trace = normalizeFridaExecutionTrace(messages, {
    sessionId: "session-1",
    pid: 13213,
    messagesTruncated: true,
  });

  expect(trace.events.map((event) => event.source.sequence)).toEqual(["2"]);
  expect(trace.coverage.rejected_records).toBe(2);
  expect(trace.coverage.records_truncated).toBe(true);
  expect(JSON.stringify(messages)).toBe(before);
});

it("keeps clock domains distinct and rejects unsafe numeric timestamps", () => {
  const base = {
    schema_version: 1,
    source: {
      provider: "ebpf",
      session_id: "run-1",
      stream_id: "cpu-0",
      retained_index: 0,
      sequence: null,
    },
    process: { pid: 7, tid: 7 },
    event: { kind: "function", phase: "enter", name: "fixture_main" },
  };
  expect(
    executionTraceEventSchema.safeParse({
      ...base,
      time: { clock: "monotonic-ns", value: "9999999999999999999" },
    }).success,
  ).toBe(true);
  expect(
    executionTraceEventSchema.safeParse({
      ...base,
      time: { clock: "qpc-ticks", value: "202", frequency_hz: "10000000" },
    }).success,
  ).toBe(true);
  expect(
    executionTraceEventSchema.safeParse({
      ...base,
      time: { clock: "monotonic-ns", value: Number("9999999999999999999") },
    }).success,
  ).toBe(false);
});

it("rejects an oversized selected value instead of copying it into trace Evidence", () => {
  const payload = eventPayload("1");
  payload.rea_trace.event.attributes["intent.path"] = "x".repeat(257);
  const trace = normalizeFridaExecutionTrace(
    [{ script_id: "agent-1", type: "send", payload }],
    { sessionId: "session-1", pid: 13213, messagesTruncated: false },
  );
  expect(trace.events).toEqual([]);
  expect(trace.coverage.rejected_records).toBe(1);
});

it("rejects an event with more than sixteen selected values", () => {
  const payload = eventPayload("1");
  Object.assign(
    payload.rea_trace.event.attributes,
    Object.fromEntries(
      Array.from({ length: 16 }, (_, index) => [`value.${index}`, "observed"]),
    ),
  );
  const trace = normalizeFridaExecutionTrace(
    [{ script_id: "agent-1", type: "send", payload }],
    { sessionId: "session-1", pid: 13213, messagesTruncated: false },
  );
  expect(trace.events).toEqual([]);
  expect(trace.coverage.rejected_records).toBe(1);
});

it("preserves explicit observed-call identity across entry and exit", () => {
  const entry = eventPayload("1");
  const exit = eventPayload("2");
  const messages = [
    {
      script_id: "agent-1",
      type: "send",
      payload: {
        rea_trace: {
          ...entry.rea_trace,
          event: {
            ...entry.rea_trace.event,
            call: { id: "7", parent_id: "2" },
          },
        },
      },
    },
    {
      script_id: "agent-1",
      type: "send",
      payload: {
        rea_trace: {
          ...exit.rea_trace,
          event: {
            ...exit.rea_trace.event,
            phase: "exit",
            call: { id: "7", parent_id: "2" },
          },
        },
      },
    },
  ];
  const trace = normalizeFridaExecutionTrace(messages, {
    sessionId: "session-1",
    pid: 13213,
    messagesTruncated: false,
  });

  expect(trace.coverage.rejected_records).toBe(0);
  expect(
    trace.events.map(({ event }) => ("call" in event ? event.call : undefined)),
  ).toEqual([
    { id: "7", parent_id: "2" },
    { id: "7", parent_id: "2" },
  ]);
});

it("rejects malformed observed-call identity", () => {
  const entry = eventPayload("1");
  const trace = normalizeFridaExecutionTrace(
    [
      {
        script_id: "agent-1",
        type: "send",
        payload: {
          rea_trace: {
            ...entry.rea_trace,
            event: {
              ...entry.rea_trace.event,
              call: { id: "01", parent_id: null },
            },
          },
        },
      },
    ],
    { sessionId: "session-1", pid: 13213, messagesTruncated: false },
  );

  expect(trace.events).toEqual([]);
  expect(trace.coverage.rejected_records).toBe(1);
});

it("preserves explicitly unknown time for an observed native call instruction", () => {
  const payload = eventPayload("1");
  const trace = normalizeFridaExecutionTrace(
    [
      {
        script_id: "stalker-agent",
        type: "send",
        payload: {
          rea_trace: {
            ...payload.rea_trace,
            time: null,
            event: {
              kind: "provider-event",
              phase: "instant",
              name: "stalker.call",
              attributes: {
                "stalker.from": "0x7ff99441f3d7",
                "stalker.to": "0x7ff99450b38c",
                "stalker.depth": "0",
              },
            },
          },
        },
      },
    ],
    { sessionId: "session-1", pid: 13213, messagesTruncated: false },
  );

  expect(trace.coverage.rejected_records).toBe(0);
  expect(trace.events).toHaveLength(1);
  expect(trace.events[0]?.time).toBeNull();
  expect(trace.events[0]?.event.kind).toBe("provider-event");
});

it("retains typed Stalker blocks without inventing a clock or function call", () => {
  const payload = eventPayload("1");
  const trace = normalizeFridaExecutionTrace(
    [
      {
        script_id: "stalker-agent",
        type: "send",
        payload: {
          rea_trace: {
            ...payload.rea_trace,
            time: null,
            event: {
              kind: "basic-block",
              phase: "execute",
              start_address: "0x7ff99441f3d7",
              end_address: "0x7ff99441f3e1",
              call: { id: "3", parent_id: null },
              attributes: { "block.start_offset": "0x5" },
            },
          },
        },
      },
    ],
    { sessionId: "session-1", pid: 13213, messagesTruncated: false },
  );

  expect(trace.coverage.rejected_records).toBe(0);
  expect(trace.events[0]?.time).toBeNull();
  expect(trace.events[0]?.event).toMatchObject({
    kind: "basic-block",
    phase: "execute",
    start_address: "0x7ff99441f3d7",
    end_address: "0x7ff99441f3e1",
    call: { id: "3", parent_id: null },
  });
});

it("retains a reconciled producer omission count separately from projection omissions", () => {
  const trace = normalizeFridaExecutionTrace(
    [
      { script_id: "agent-1", type: "send", payload: eventPayload("1") },
      {
        script_id: "agent-1",
        type: "send",
        payload: {
          rea_trace_status: {
            schema_version: 1,
            pid: 13213,
            emitted_events: 1,
            omitted_events: 34,
            producer_lost_events: null,
          },
        },
      },
    ],
    { sessionId: "session-1", pid: 13213, messagesTruncated: false },
  );
  expect(trace.coverage.omitted_events).toBe(0);
  expect(trace.coverage.producer_omitted_events).toBe(34);
  expect(executionTraceBatchSchema.safeParse(trace).success).toBe(true);
});

it("reports selection filtering separately from producer omission", () => {
  const status = {
    schema_version: 1,
    pid: 13213,
    emitted_events: 1,
    omitted_events: 2,
    filtered_events: 59,
    producer_lost_events: null,
  };
  const event = {
    script_id: "agent-1",
    type: "send",
    payload: eventPayload("1"),
  };
  const messages = [
    event,
    {
      script_id: "agent-1",
      type: "send",
      payload: { rea_trace_status: status },
    },
  ];
  const trace = normalizeFridaExecutionTrace(messages, {
    sessionId: "session-1",
    pid: 13213,
    messagesTruncated: false,
  });
  expect(trace.coverage.producer_omitted_events).toBe(2);
  expect(trace.coverage.producer_filtered_events).toBe(59);
  expect(executionTraceBatchSchema.safeParse(trace).success).toBe(true);

  const invalid = normalizeFridaExecutionTrace(
    [
      event,
      {
        script_id: "agent-1",
        type: "send",
        payload: { rea_trace_status: { ...status, filtered_events: -1 } },
      },
    ],
    { sessionId: "session-1", pid: 13213, messagesTruncated: false },
  );
  expect(invalid.coverage.producer_omitted_events).toBeNull();
  expect(invalid.coverage.producer_filtered_events).toBeNull();
});

it("does not accept a producer omission snapshot preceding later trace events", () => {
  const trace = normalizeFridaExecutionTrace(
    [
      { script_id: "agent-1", type: "send", payload: eventPayload("1") },
      {
        script_id: "agent-1",
        type: "send",
        payload: {
          rea_trace_status: {
            schema_version: 1,
            pid: 13213,
            emitted_events: 1,
            omitted_events: 34,
            producer_lost_events: null,
          },
        },
      },
      { script_id: "agent-1", type: "send", payload: eventPayload("2") },
    ],
    { sessionId: "session-1", pid: 13213, messagesTruncated: false },
  );
  expect(trace.events).toHaveLength(2);
  expect(trace.coverage.producer_omitted_events).toBeNull();
});

it("does not trust a producer omission snapshot when emitted sequences are discontinuous", () => {
  const status = {
    script_id: "agent-1",
    type: "send",
    payload: {
      rea_trace_status: {
        schema_version: 1,
        pid: 13213,
        emitted_events: 2,
        omitted_events: 34,
        producer_lost_events: null,
      },
    },
  };
  for (const sequences of [
    ["1", "1"],
    ["1", "3"],
    ["2", "1"],
    ["2", "3"],
  ]) {
    const trace = normalizeFridaExecutionTrace(
      [
        ...sequences.map((sequence) => ({
          script_id: "agent-1",
          type: "send",
          payload: eventPayload(sequence),
        })),
        status,
      ],
      { sessionId: "session-1", pid: 13213, messagesTruncated: false },
    );
    expect(trace.events.map((event) => event.source.sequence)).toEqual(
      sequences,
    );
    expect(trace.coverage.producer_omitted_events).toBeNull();
  }
});

it("leaves producer omission unknown when status identity or retention is uncertain", () => {
  const event = {
    script_id: "agent-1",
    type: "send",
    payload: eventPayload("1"),
  };
  const status = {
    script_id: "agent-1",
    type: "send",
    payload: {
      rea_trace_status: {
        schema_version: 1,
        pid: 13213,
        emitted_events: 1,
        omitted_events: 34,
        producer_lost_events: null,
      },
    },
  };
  const cases = [
    { messages: [event, { ...status, script_id: "agent-2" }] },
    {
      messages: [
        event,
        {
          ...status,
          payload: {
            rea_trace_status: {
              ...status.payload.rea_trace_status,
              pid: 99,
            },
          },
        },
      ],
    },
    {
      messages: [
        event,
        {
          ...status,
          payload: {
            rea_trace_status: {
              ...status.payload.rea_trace_status,
              emitted_events: 2,
            },
          },
        },
      ],
    },
    { messages: [event, status, status] },
    { messages: [event, status], messagesTruncated: true },
  ];

  for (const candidate of cases) {
    const trace = normalizeFridaExecutionTrace(candidate.messages, {
      sessionId: "session-1",
      pid: 13213,
      messagesTruncated: candidate.messagesTruncated ?? false,
    });
    expect(trace.coverage.producer_omitted_events).toBeNull();
  }
});

it("projects one selected script's status without mixing another script's trace", () => {
  const status = (omittedEvents: number, filteredEvents: number) => ({
    schema_version: 1,
    pid: 13213,
    emitted_events: 1,
    omitted_events: omittedEvents,
    filtered_events: filteredEvents,
    producer_lost_events: null,
  });
  const messages = [
    { script_id: "agent-1", type: "send", payload: eventPayload("1") },
    { script_id: "agent-2", type: "send", payload: eventPayload("1") },
    {
      script_id: "agent-1",
      type: "send",
      payload: { rea_trace_status: status(2, 3) },
    },
    {
      script_id: "agent-2",
      type: "send",
      payload: { rea_trace_status: status(5, 7) },
    },
  ];
  const session = {
    sessionId: "session-1",
    pid: 13213,
    messagesTruncated: false,
    selectedScriptId: "agent-1",
  };
  const selected = normalizeFridaExecutionTrace(messages, session);
  expect(executionTraceBatchSchema.safeParse(selected).success).toBe(true);
  expect(selected.events.map((event) => event.source.retained_index)).toEqual([
    0,
  ]);
  expect(selected.coverage).toMatchObject({
    retained_records: 4,
    candidate_records: 1,
    rejected_records: 0,
    reader_filtered_records: 2,
    producer_omitted_events: 2,
    producer_filtered_events: 3,
    producer_lost_events: null,
  });

  const second = normalizeFridaExecutionTrace(messages, {
    ...session,
    selectedScriptId: "agent-2",
  });
  expect(second.events.map((event) => event.source.retained_index)).toEqual([
    1,
  ]);
  expect(second.coverage).toMatchObject({
    reader_filtered_records: 2,
    producer_omitted_events: 5,
    producer_filtered_events: 7,
  });

  const truncated = normalizeFridaExecutionTrace(messages, {
    ...session,
    messagesTruncated: true,
  });
  expect(truncated.coverage.producer_omitted_events).toBeNull();

  const wholeSession = normalizeFridaExecutionTrace(messages, {
    sessionId: session.sessionId,
    pid: session.pid,
    messagesTruncated: false,
  });
  expect(wholeSession.events).toHaveLength(2);
  expect(wholeSession.coverage.producer_omitted_events).toBeNull();
});

it("rejects an empty or oversized selected script identity", () => {
  for (const selectedScriptId of ["", "x".repeat(257)]) {
    expect(() =>
      normalizeFridaExecutionTrace([], {
        sessionId: "session-1",
        pid: 13213,
        messagesTruncated: false,
        selectedScriptId,
      }),
    ).toThrow();
  }
});
