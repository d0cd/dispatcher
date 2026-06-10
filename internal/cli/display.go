package cli

import "fmt"

// formatCost prints sub-cent values with 4 decimals so a real "<$0.01"
// run isn't indistinguishable from "$0.00". A zero cost renders as "$0.00"
// ("free this month / nothing to run" is a real answer); only negative values
// — always bugs (clock skew or arithmetic underflow) — render blank. Used by
// list, status, history, cost, run, and bill so cost display is consistent.
func formatCost(v float64) string {
	switch {
	case v < 0:
		return ""
	case v == 0:
		return "$0.00"
	case v < 0.01:
		return fmt.Sprintf("$%.4f", v)
	default:
		return fmt.Sprintf("$%.2f", v)
	}
}
