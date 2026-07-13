//go:build linux

// Command dispatcher-nitro-proxy runs on the Nitro parent instance and bridges
// dispatcher's TCP connection to the enclave's vsock port. A Nitro enclave has no
// network stack — only a vsock channel to its parent — so dispatcher reaches the
// in-enclave agent through this forwarder. The channel is untrusted (as with the
// other clouds): attestation + sealing are the security boundary, not the proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mdlayher/vsock"
)

// maxConns bounds concurrent bridges so a peer can't exhaust parent fds / enclave
// vsock buffers by opening unbounded connections.
const maxConns = 64

func main() {
	tcpAddr := flag.String("tcp", ":8443", "TCP listen address (dispatcher-facing)")
	cid := flag.Uint("cid", 0, "enclave context id (from nitro-cli describe-enclaves)")
	vport := flag.Uint("vsock-port", 8443, "enclave vsock port")
	flag.Parse()

	l, err := net.Listen("tcp", *tcpAddr)
	if err != nil {
		log.Fatal(err)
	}

	// Close the listener on SIGINT/SIGTERM so Accept returns and we drain.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); _ = l.Close() }()

	log.Printf("dispatcher-nitro-proxy %s -> vsock(cid=%d port=%d)", *tcpAddr, *cid, *vport)
	sem := make(chan struct{}, maxConns)
	for {
		conn, err := l.Accept()
		if err != nil {
			// A closed listener (shutdown) is terminal; any other error is
			// transient (EMFILE/ECONNABORTED) — log and keep serving instead of
			// exiting and tearing down every in-flight bridge.
			if errors.Is(err, net.ErrClosed) {
				log.Print("listener closed; shutting down")
				return
			}
			log.Printf("accept: %v (continuing)", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case sem <- struct{}{}:
			go func() { defer func() { <-sem }(); bridge(conn, uint32(*cid), uint32(*vport)) }()
		default:
			log.Print("connection cap reached; rejecting")
			_ = conn.Close()
		}
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
