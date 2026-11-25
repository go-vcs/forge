//go:build !darwin && !linux

package main

import (
	"context"
	"errors"

	"github.com/go-vcs/forge/internal/adminclient"
)

func platformSigner(context.Context) (adminclient.Signer, error) {
	return nil, errors.New("forgectl: no FIDO2 key access on this operating system (macOS and Linux only)")
}
