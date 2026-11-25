//go:build linux

package main

import (
	"context"

	linuxfido "github.com/go-gnulinux/fido"

	"github.com/go-vcs/forge/internal/adminclient"
)

func platformSigner(ctx context.Context) (adminclient.Signer, error) {
	k, err := linuxfido.Open(ctx)
	if err != nil {
		return nil, err
	}
	return adminclient.FIDOSigner{Key: k}, nil
}
