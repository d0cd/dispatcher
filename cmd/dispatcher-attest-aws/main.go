// Command dispatcher-attest-aws is the in-TEE agent for AWS SEV-SNP confidential
// runs. It is the same HTTP sealed-exchange agent as dispatcher-attest, but
// attests via a raw SEV-SNP report from /dev/sev-guest instead of a vendor token.
// dispatcher scps this binary onto a booted SEV-SNP instance and starts it.
package main

import (
	"flag"
	"log"
	"os"

	"github.com/d0cd/dispatcher/internal/cloudvm"
)

func main() {
	addr := flag.String("addr", envOr("DISPATCHER_ATTEST_ADDR", ":8443"), "listen address")
	flag.Parse()

	log.Printf("dispatcher-attest-aws listening on %s", *addr)
	if err := cloudvm.RunAWSAgent(*addr); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
