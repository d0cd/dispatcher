package run

import "time"

// TraceEvent is one record in the Chrome Trace Event Format, consumed by
// chrome://tracing and https://ui.perfetto.dev.
type TraceEvent struct {
	Name string         `json:"name"`
	Cat  string         `json:"cat,omitempty"`
	Ph   string         `json:"ph"`            // "X" = complete (has dur); "M" = metadata
	Ts   int64          `json:"ts"`            // start, microseconds since epoch
	Dur  int64          `json:"dur,omitempty"` // duration, microseconds
	Pid  int            `json:"pid"`
	Tid  int            `json:"tid"`
	Args map[string]any `json:"args,omitempty"`
}

// TraceOutput is the top-level Chrome trace document.
type TraceOutput struct {
	TraceEvents     []TraceEvent `json:"traceEvents"`
	DisplayTimeUnit string       `json:"displayTimeUnit"`
}

// BuildTrace renders a run's phase timeline as a Chrome/Perfetto trace: one
// complete event per phase, spanning from when the run entered that state until
// it entered the next one (or FinishedAt for the last phase).
func BuildTrace(rec *RunRecord) TraceOutput {
	out := TraceOutput{DisplayTimeUnit: "ms"}
	out.TraceEvents = append(out.TraceEvents, TraceEvent{
		Name: "process_name", Ph: "M", Pid: 1, Tid: 1,
		Args: map[string]any{"name": "run " + rec.ID},
	})

	for i, m := range rec.Timeline {
		end := phaseEnd(i, rec.Timeline, rec.FinishedAt)
		dur := end.Sub(m.EnteredAt)
		if dur < 0 {
			dur = 0
		}
		out.TraceEvents = append(out.TraceEvents, TraceEvent{
			Name: string(m.State),
			Cat:  "phase",
			Ph:   "X",
			Ts:   m.EnteredAt.UnixMicro(),
			Dur:  dur.Microseconds(),
			Pid:  1,
			Tid:  1,
		})
	}
	return out
}

// phaseEnd is when phase i ended: the next phase's start, or FinishedAt for the
// last phase. A still-running run (no FinishedAt) leaves the final phase open,
// which BuildTrace renders as zero duration rather than negative.
func phaseEnd(i int, marks []PhaseMark, finishedAt time.Time) time.Time {
	if i+1 < len(marks) {
		return marks[i+1].EnteredAt
	}
	if !finishedAt.IsZero() {
		return finishedAt
	}
	return marks[i].EnteredAt
}
