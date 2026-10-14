import { z } from "zod";

export const executionTraceIntegerSchema = z
  .string()
  .regex(/^(0|[1-9][0-9]*)$/u);
const positiveDecimalInteger = z.string().regex(/^[1-9][0-9]*$/u);

/** Keep each producer's clock domain explicit; integer values remain exact in JSON. */
export const executionTraceTimeSchema = z.discriminatedUnion("clock", [
  z.strictObject({
    clock: z.literal("unix-epoch-ms"),
    value: executionTraceIntegerSchema,
  }),
  z.strictObject({
    clock: z.literal("monotonic-ns"),
    value: executionTraceIntegerSchema,
  }),
  z.strictObject({
    clock: z.literal("qpc-ticks"),
    value: executionTraceIntegerSchema,
    frequency_hz: positiveDecimalInteger,
  }),
  z.strictObject({
    /** Windows FILETIME: 100 ns intervals since 1601-01-01T00:00:00Z. */
    clock: z.literal("windows-filetime-100ns"),
    value: executionTraceIntegerSchema,
  }),
]);

const name = z.string().min(1).max(1024);
/** Exact observed native pointer; never pass addresses through a JSON number. */
const nativeAddress = z.string().regex(/^0x[0-9a-f]{1,16}$/iu);
const attributes = z
  .record(z.string().min(1).max(64), z.string().max(256).nullable())
  .refine(
    (value) => Object.keys(value).length <= 16,
    "Too many selected values",
  )
  .optional();
/** Producer-assigned identity within one stream. A null parent means no selected parent was observed. */
const observedCall = z
  .strictObject({
    id: executionTraceIntegerSchema,
    parent_id: executionTraceIntegerSchema.nullable(),
  })
  .optional();
/** A common event vocabulary; provider-specific observations remain in raw Evidence. */
export const executionTraceActionSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    /** Preserve a provider event when no stronger process/call meaning is known. */
    kind: z.literal("provider-event"),
    phase: z.literal("instant"),
    name,
    attributes,
  }),
  z.strictObject({
    /** One observed block execution, with provider-reported address bounds. */
    kind: z.literal("basic-block"),
    phase: z.literal("execute"),
    start_address: nativeAddress,
    end_address: nativeAddress,
    attributes,
    call: observedCall,
  }),
  z.strictObject({
    kind: z.literal("function"),
    phase: z.enum(["enter", "exit"]),
    name,
    attributes,
    call: observedCall,
  }),
  z.strictObject({
    kind: z.literal("syscall"),
    phase: z.enum(["enter", "exit"]),
    name,
    attributes,
    call: observedCall,
  }),
  z.strictObject({
    kind: z.literal("process"),
    phase: z.enum(["start", "end"]),
    name,
    attributes,
  }),
  z.strictObject({
    kind: z.literal("thread"),
    phase: z.enum(["start", "end"]),
    name,
    attributes,
  }),
  z.strictObject({
    kind: z.literal("module"),
    phase: z.enum(["load", "unload"]),
    name,
    attributes,
  }),
]);

/** One selected runtime event, with only per-source order and clock claims. */
export const executionTraceEventSchema = z.strictObject({
  schema_version: z.literal(1),
  source: z.strictObject({
    provider: z.string().min(1).max(128),
    session_id: z.string().min(1).max(256),
    stream_id: z.string().min(1).max(256).nullable(),
    /** Index within the retained raw-record array; earlier records may be evicted. */
    retained_index: z.number().int().nonnegative(),
    /** Producer claim; it does not establish ordering across streams. */
    sequence: executionTraceIntegerSchema.nullable(),
  }),
  time: executionTraceTimeSchema.nullable(),
  process: z.strictObject({
    pid: z.number().int().nonnegative(),
    tid: z.number().int().nonnegative().nullable(),
  }),
  event: executionTraceActionSchema,
});

export type ExecutionTraceEvent = z.infer<typeof executionTraceEventSchema>;

/** Retention and parsing facts, not complete program coverage. Event indexes refer to retained raw records. */
const executionTraceBatchShape = z.strictObject({
  schema_version: z.literal(1),
  events: z.array(executionTraceEventSchema),
  provenance: z.strictObject({
    raw_record_kind: z.string().min(1).max(128),
    process_id: z.string().min(1).max(128),
    thread_id: z.string().min(1).max(128),
    timestamp: z.string().min(1).max(128),
    sequence: z.string().min(1).max(128),
    attributes: z.string().min(1).max(128),
  }),
  coverage: z.strictObject({
    retained_records: z.number().int().nonnegative(),
    candidate_records: z.number().int().nonnegative(),
    rejected_records: z.number().int().nonnegative(),
    omitted_events: z.number().int().nonnegative(),
    records_truncated: z.boolean(),
    /** Reader-reported raw records excluded by its selector before retention. */
    reader_filtered_records: z
      .number()
      .int()
      .nonnegative()
      .nullable()
      .optional(),
    /** Producer-reported cap/filter omission; absent in earlier local v1 records. */
    producer_omitted_events: z
      .number()
      .int()
      .nonnegative()
      .nullable()
      .optional(),
    /** Producer-reported events excluded by its selection predicate. */
    producer_filtered_events: z
      .number()
      .int()
      .nonnegative()
      .nullable()
      .optional(),
    producer_lost_events: z.number().int().nonnegative().nullable(),
  }),
});

export const executionTraceBatchSchema = executionTraceBatchShape.superRefine(
  (batch, context) => {
    if (batch.coverage.candidate_records > batch.coverage.retained_records)
      context.addIssue({
        code: "custom",
        path: ["coverage", "candidate_records"],
        message: "Candidate records cannot exceed retained raw records",
      });
    if (batch.coverage.rejected_records > batch.coverage.candidate_records)
      context.addIssue({
        code: "custom",
        path: ["coverage", "rejected_records"],
        message: "Rejected records cannot exceed candidate records",
      });
    for (const [index, event] of batch.events.entries()) {
      if (event.source.retained_index >= batch.coverage.retained_records)
        context.addIssue({
          code: "custom",
          path: ["events", index, "source", "retained_index"],
          message: "Event index must refer to a retained raw record",
        });
    }
  },
);

export type ExecutionTraceBatch = z.infer<typeof executionTraceBatchSchema>;
