package cloudvm

// secret wraps an in-process credential (e.g. a REST provider's API key) so it
// cannot be accidentally logged, formatted, or serialized. Its String/GoString/
// MarshalText/MarshalJSON all redact, so `%v`, `%s`, `%#v`, log lines, and JSON
// records show "[REDACTED]" instead of the value. The raw credential is only
// reachable via reveal() — every call site of which is the audit surface for
// where the secret actually leaves this boundary (the Authorization header).
//
// This matters because REST providers (unlike the CLI-delegated ones) hold the
// credential in dispatcher's own process; the type makes the safe path the
// default and the exposing path explicit.
//
// Caveat: fmt CANNOT invoke this redaction when the secret is an UNEXPORTED field
// of another struct (reflection can't call methods on unexported fields), so a
// struct holding a secret must redact itself via its own String/GoString (see
// LambdaProvider/LambdaFetcher). JSON marshaling is unaffected — MarshalJSON is
// honored through struct fields.
type secret string

func (secret) String() string   { return redacted }
func (secret) GoString() string { return redacted }

func (secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// reveal returns the raw credential. Keep call sites minimal and reviewable.
func (s secret) reveal() string { return string(s) }

// empty reports whether no credential is set.
func (s secret) empty() bool { return s == "" }

const redacted = "[REDACTED]"
