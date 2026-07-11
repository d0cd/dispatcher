//go:build linux

// Command dispatcher-attest-nitro is the in-enclave agent for AWS Nitro Enclaves
// confidential runs. It is the same sealed-exchange agent as the other clouds, but
// served over vsock and attesting via the Nitro Security Module (/dev/nsm) instead
// of a vendor token or a raw SEV-SNP report. It runs inside the measured enclave
// image (its PCR0 is the attested identity); the parent instance proxies
// dispatcher's TCP connection to this agent's vsock port.
package main

import (
	"flag"
	"log"
	"os"
	"strconv"

	nitroagent "github.com/d0cd/dispatcher/internal/attest/agent/nitro"
)

func main() {
	port := flag.Uint("port", envUint("DISPATCHER_ATTEST_VSOCK_PORT", 8443), "vsock port to listen on")
	flag.Parse()

	log.Printf("dispatcher-attest-nitro listening on vsock port %d", *port)
	if err := nitroagent.RunAgent(uint32(*port)); err != nil {
		log.Fatal(err)
	}
}

func envUint(key string, def uint) uint {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			return uint(n)
		}
	}
	return def
}
