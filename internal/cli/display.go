package cli

import "fmt"

// formatCost prints sub-cent values with 4 decimals so a real "<$0.01"
// run isn't indistinguishable from "$0.00 unknown". Used by list, status,
// history, cost, run, and bill so cost display is consistent everywhere.
// Negative values are clamped to 0 — they're always bugs (clock skew or
// arithmetic underflow) and would be visually misleading.
func formatCost(v float64) string {
	switch {
	case v <= 0:
		return ""
	case v < 0.01:
		return fmt.Sprintf("$%.4f", v)
	default:
		return fmt.Sprintf("$%.2f", v)
	}
}
