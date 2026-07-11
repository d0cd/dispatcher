//go:build linux

// Command dispatcher-nitro-proxy runs on the Nitro parent instance and bridges
// dispatcher's TCP connection to the enclave's vsock port. A Nitro enclave has no
// network stack — only a vsock channel to its parent — so dispatcher reaches the
// in-enclave agent through this forwarder. The channel is untrusted (as with the
// other clouds): attestation + sealing are the security boundary, not the proxy.
package main

import (
	"flag"
	"io"
	"log"
	"net"

	"github.com/mdlayher/vsock"
)

func main() {
	tcpAddr := flag.String("tcp", ":8443", "TCP listen address (dispatcher-facing)")
	cid := flag.Uint("cid", 0, "enclave context id (from nitro-cli describe-enclaves)")
	vport := flag.Uint("vsock-port", 8443, "enclave vsock port")
	flag.Parse()

	l, err := net.Listen("tcp", *tcpAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("dispatcher-nitro-proxy %s -> vsock(cid=%d port=%d)", *tcpAddr, *cid, *vport)
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go bridge(conn, uint32(*cid), uint32(*vport))
	}
}

// bridge pipes a client TCP connection to a fresh vsock connection to the enclave,
// in both directions, until either side closes.
func bridge(client net.Conn, cid, port uint32) {
	defer client.Close()
	enclave, err := vsock.Dial(cid, port, nil)
	if err != nil {
		log.Printf("dial enclave vsock(%d:%d): %v", cid, port, err)
		return
	}
	defer enclave.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(enclave, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, enclave); done <- struct{}{} }()
	<-done
}
