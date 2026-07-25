package run

// ActiveSpend sums the accumulated cost of non-terminal runs — the money
// currently at risk from still-billing (possibly forgotten) runs — and returns
// that total in USD plus the run count. It is local only: it reads run records
// and never calls a cloud API, so it is cheap enough to run on every `status`.
// Terminal runs are already torn down and zero-cost runs (e.g. local process)
// aren't a billing risk, so neither is counted.
func ActiveSpend() (total float64, count int) {
	ids, err := ListRecords()
	if err != nil {
		return 0, 0
	}
	for _, id := range ids {
		rec, err := LoadRecord(id)
		if err != nil || rec.State.IsTerminal() || rec.Cost.Value <= 0 {
			continue
		}
		total += rec.Cost.Value
		count++
	}
	return total, count
}
