// Command dispatcher-attest-azure is the in-TEE agent for Azure confidential
// (SEV-SNP CVM) runs. It is the same HTTP sealed-exchange agent as
// dispatcher-attest, but attests via Microsoft Azure Attestation (MAA) over the
// vTPM instead of the GCP Confidential Space teeserver. dispatcher scps this
// binary onto a booted CVM and starts it. See docs/confidential-azure-maa.md.
package main

import (
	"flag"
	"log"
	"os"

	"github.com/d0cd/dispatcher/internal/cloudvm"
)

func main() {
	addr := flag.String("addr", envOr("DISPATCHER_ATTEST_ADDR", ":8443"), "listen address")
	maaURL := flag.String("maa-url", envOr("DISPATCHER_MAA_URL", "https://sharedeus.eus.attest.azure.net"), "MAA instance URL")
	flag.Parse()

	log.Printf("dispatcher-attest-azure listening on %s (maa=%s)", *addr, *maaURL)
	if err := cloudvm.RunAzureAgent(*addr, *maaURL); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
