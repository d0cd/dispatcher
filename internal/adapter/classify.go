package adapter

import "strings"

// MaxFailureMessageLen bounds how much of an adapter-reported failure message
// we keep. Container/process stderr can contain workload-private data
// (secrets, customer payloads, internal endpoints) — short, structured
// summaries are operationally useful; full stderr dumps are a data-leak
// surface in logs and persisted run records.
const MaxFailureMessageLen = 160

// truncateFailureMessage clamps a message to MaxFailureMessageLen runes and
// appends "…" when truncation occurred. Multi-line input collapses to the
// first non-empty line so the message is still scannable in one-line UI.
func truncateFailureMessage(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if len(s) <= MaxFailureMessageLen {
		return s
	}
	return s[:MaxFailureMessageLen] + "…"
}

// FailureKind classifies whether a failed run is worth retrying.
//
// Most workload failures (syntax errors, missing dependencies, logic bugs)
// will fail the same way on retry — retrying them wastes time and money.
// The classifier is deliberately conservative: it returns Transient only
// when there's a specific signal that the failure was environmental.
type FailureKind string

const (
	// FailurePermanent means a retry would likely fail the same way:
	// non-zero exit from the workload itself, a syntax error, a logic bug.
	FailurePermanent FailureKind = "permanent"

	// FailureTransient means the failure was environmental (OOM kill,
	// preemption, infrastructure signal) and a retry has a real chance of
	// succeeding. Use sparingly — most "transient" guesses are wrong.
	FailureTransient FailureKind = "transient"

	// FailureUnknown means the adapter couldn't surface enough detail to
	// classify. Treated as permanent for retry decisions; treated as
	// "investigate manually" for the user.
	FailureUnknown FailureKind = "unknown"
)

// ClassifyFailure inspects FailureDetails and decides whether a retry is
// appropriate. The rules:
//
//   - OOMKilled → transient. Memory pressure is environmental; retrying on
//     a larger instance (or hoping a co-tenant freed memory) can succeed.
//   - SIGKILL (without OOM flag) → transient. Possibly OOM that the adapter
//     couldn't confirm, possibly preemption, possibly external kill.
//   - SIGTERM → transient. Almost always the platform terminating us.
//   - An exit code that ENCODES a KILL/TERM signal → transient. Adapters that
//     only capture `$?` (the cloud SSH runner) can't set Signal, so a signal
//     kill arrives as 128+signal (137=SIGKILL) or a runtime's unsigned wrap of
//     a negative return code (256-signal: 247=Python's -9). A crash signal
//     (SIGSEGV etc.) is a workload defect and stays permanent.
//   - Empty FailureDetails (no signal we can read) → unknown.
//   - Any other non-zero exit code → permanent. Workload-specific failure.
//
// New cases should err on the side of permanent. The cost of a wrong
// "transient" classification (paying for a retry that re-fails) is higher
// than the cost of a wrong "permanent" classification (user reruns
// manually).
func ClassifyFailure(d FailureDetails) FailureKind {
	if d.OOMKilled {
		return FailureTransient
	}
	switch d.Signal {
	case "killed", "SIGKILL", "SIGTERM", "terminated":
		return FailureTransient
	}
	if killSignalExit(d.ExitCode) {
		return FailureTransient
	}
	if d.ExitCode == 0 && d.Signal == "" && d.Message == "" {
		return FailureUnknown
	}
	return FailurePermanent
}

// killSignalExit reports whether a raw process exit code encodes termination by
// a KILL or TERM signal — probably environmental (OOM/preemption) rather than a
// workload bug. Two encodings are recognized: the shell's 128+signal convention
// (137=SIGKILL, 143=SIGTERM) and the unsigned-byte wrap of a negative return code
// that runtimes like Python emit (256-signal: 247=SIGKILL, 241=SIGTERM). Crash
// signals (SIGSEGV, SIGABRT, …) are deliberately excluded: a crash is a defect,
// not something a retry fixes.
func killSignalExit(code int) bool {
	var sig int
	switch {
	case code > 128 && code < 192: // 128 + signal
		sig = code - 128
	case code >= 241 && code <= 255: // 256 - signal (unsigned wrap of -signal)
		sig = 256 - code
	default:
		return false
	}
	return sig == 9 || sig == 15 // SIGKILL, SIGTERM
}
