package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/fatih/color"

	"github.com/d0cd/dispatcher/internal/cloudvm"
)

// loadLiveCatalog runs every configured provider's pricing fetcher in parallel
// and returns the merged catalog plus any providers that were skipped because
// credentials are missing. The caller is expected to surface skipped providers
// to the user (they'll be absent from cost comparisons).
//
// A 30-second timeout caps the wait so a hung provider can't stall the whole
// plan command.
//
// Set DISPATCHER_DISABLE_LIVE_PRICING=1 to bypass the live fetch entirely.
// Used by tests so the suite isn't gated on real outbound network calls.
func loadLiveCatalog(stderr io.Writer) *cloudvm.Catalog {
	if os.Getenv("DISPATCHER_DISABLE_LIVE_PRICING") != "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fetchers := []cloudvm.Fetcher{
		cloudvm.NewHetznerFetcher(),
		cloudvm.NewAzureFetcher(""),
		cloudvm.NewAWSFetcher(""),
		cloudvm.NewGCPFetcher(""),
	}

	cat, skipped, err := cloudvm.NewLiveCatalog(ctx, fetchers...)
	if err != nil {
		dim := color.New(color.Faint)
		dim.Fprintf(stderr, "Live pricing unavailable: %v\n", err)
		dim.Fprintln(stderr, "Falling back to built-in estimates (confidence: low).")
		return nil
	}
	if ctx.Err() != nil {
		// All fetchers were skipped via timeout. NewLiveCatalog returned an
		// empty catalog rather than an error, but we shouldn't pretend the
		// estimates are live.
		dim := color.New(color.Faint)
		dim.Fprintln(stderr, "Live pricing fetch timed out. Falling back to built-in estimates (confidence: low).")
		return nil
	}

	if len(skipped) > 0 {
		dim := color.New(color.Faint)
		for _, s := range skipped {
			dim.Fprintf(stderr, "Skipped %s pricing: %s\n", s.Provider, s.Reason)
		}
	}

	return cat
}

// formatPricingFootnote returns a short footer summarizing how pricing was
// sourced. Empty when there's nothing useful to say.
func formatPricingFootnote(cat *cloudvm.Catalog) string {
	if cat == nil {
		return "pricing: offline (using built-in estimates)"
	}
	providers := cat.Providers()
	if len(providers) == 0 {
		return ""
	}
	return fmt.Sprintf("pricing: live from %v", providers)
}
