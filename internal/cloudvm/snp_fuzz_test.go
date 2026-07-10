package cloudvm

import "testing"

// FuzzParseSNPReport feeds arbitrary bytes to the AMD SEV-SNP report parser — a
// binary-format decoder over attacker-influenceable input, the class of code
// where fuzzing earns its keep (out-of-bounds, slice panics). The property under
// test is total safety: parseSNPReport must return an error or a report for ANY
// input, never panic, and claims() on a parsed report must be panic-safe too.
//
//	go test ./internal/cloudvm -run x -fuzz FuzzParseSNPReport -fuzztime 60s
func FuzzParseSNPReport(f *testing.F) {
	// Seeds spanning the length guard: empty, just-short, exact, and oversized.
	f.Add([]byte{})
	f.Add(make([]byte, snpReportLen-1))
	f.Add(make([]byte, snpReportLen))
	f.Add(make([]byte, snpReportLen+512))

	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := parseSNPReport(b)
		if err != nil {
			return
		}
		// A successful parse must project to claims without panicking — the
		// length guard has to cover every field offset the projection reads.
		_ = r.claims()
	})
}
