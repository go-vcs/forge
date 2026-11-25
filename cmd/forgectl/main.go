// Command forgectl administers a go-vcs forge. Every change is authorized by a
// touch (and verification) on the administrator's FIDO2 hardware key; nothing
// secret is ever read from arguments or the environment.
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
