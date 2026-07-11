// Command dispatcher-attest is the in-TEE agent for GCP Confidential Space runs.
// It is baked into the measured workload container (its image digest is the
// attested identity), serves attestation evidence and the sealed-payload
// exchange over the untrusted TCP channel, and runs the workload inside the TEE.
// See docs/confidential-space-execution.md.
package main

import (
	"flag"
	"log"
	"os"

	"github.com/d0cd/dispatcher/internal/attest"
)

func main() {
	addr := flag.String("addr", envOr("DISPATCHER_ATTEST_ADDR", ":8443"), "listen address")
	audience := flag.String("audience", envOr("DISPATCHER_ATTEST_AUDIENCE", "dispatcher"), "attestation token audience")
	flag.Parse()

	log.Printf("dispatcher-attest listening on %s (audience=%s)", *addr, *audience)
	if err := attest.RunAgent(*addr, *audience); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
