// Command forge is the go-vcs forge server. Milestone 2a ships its admin API:
// `forge serve` listens for the FIDO2-authenticated admin gRPC API on TLS 1.3
// and for enrolment on a local Unix socket. Administration is done with
// forgectl.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// osExit is replaced by tests.
var osExit = os.Exit

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := RootCmd().ExecuteContext(ctx); err != nil {
		stop()
		osExit(1)
	}
}
