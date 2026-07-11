//go:build linux

// Command dispatcher-attest-azuresnp is the in-CVM agent for Azure confidential
// VMs using direct SEV-SNP + vTPM attestation (no MAA). It serves the sealed
// exchange and returns SNP report + HCL runtime data + an AK-signed PCR11 quote.
// It is baked into the measured UKI image (its PCR11 is the attested identity).
// See docs/confidential-azure-uki.md.
package main

import (
	"flag"
	"log"
	"os"

	azuresnpagent "github.com/d0cd/dispatcher/internal/attest/agent/azuresnp"
)

func main() {
	addr := flag.String("addr", envOr("DISPATCHER_ATTEST_ADDR", ":8443"), "listen address")
	flag.Parse()

	log.Printf("dispatcher-attest-azuresnp listening on %s", *addr)
	if err := azuresnpagent.RunAgent(*addr); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
