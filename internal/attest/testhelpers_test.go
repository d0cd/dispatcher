package attest

// assertErr is a trivial error for table tests.
type assertErr string

func (e assertErr) Error() string { return string(e) }
