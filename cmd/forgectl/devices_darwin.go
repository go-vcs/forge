//go:build darwin

package main

import (
	"context"

	macfido "github.com/go-macos/fido"

	"github.com/go-vcs/forge/internal/adminclient"
)

func platformSigner(ctx context.Context) (adminclient.Signer, error) {
	k, err := macfido.Open(ctx)
	if err != nil {
		return nil, err
	}
	return adminclient.FIDOSigner{Key: k}, nil
}
