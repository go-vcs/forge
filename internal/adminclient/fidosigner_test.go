// Copyright (c) the go-vcs authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package adminclient_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-authn/fido"

	"github.com/go-vcs/forge/internal/adminclient"
	"github.com/go-vcs/forge/internal/fidotest"
)

// fakeKey is a CTAPHID device that answers INIT itself and hands every CBOR
// command to handle, whose result is the reply payload (status byte first).
type fakeKey struct {
	handle func(cmd byte, params []byte) []byte
	got    []byte // the last CBOR command's parameters
	cmd    byte
	reasm  map[uint32]*fido.Reassembler
	queue  [][]byte
	closed bool
}

func newFakeKey(handle func(cmd byte, params []byte) []byte) *fakeKey {
	return &fakeKey{handle: handle, reasm: map[uint32]*fido.Reassembler{}}
}

const fakeChannel = 0x01020304

func (k *fakeKey) Name() string { return "fake key" }
func (k *fakeKey) Close() error { k.closed = true; return nil }

func (k *fakeKey) Send(p []byte) error {
	ch := binary.BigEndian.Uint32(p[:4])
	r := k.reasm[ch]
	if r == nil {
		r = fido.NewReassembler(ch)
		k.reasm[ch] = r
	}
	msg, done, err := r.Feed(p)
	if err != nil {
		return err
	}
	if !done {
		return nil
	}
	delete(k.reasm, ch)
	var (
		reply []byte
		rch   = ch
		cmd   = msg.Cmd
	)
	switch msg.Cmd {
	case fido.CmdInit:
		reply = append(reply, msg.Data[:8]...)
		reply = binary.BigEndian.AppendUint32(reply, fakeChannel)
		reply = append(reply, 2, 1, 0, 0, byte(fido.CapCBOR))
	case fido.CmdCBOR:
		k.cmd, k.got = msg.Data[0], msg.Data[1:]
		reply = k.handle(k.cmd, k.got)
	default:
		return errors.New("fake key: unexpected command")
	}
	packets, err := fido.Split(rch, cmd, reply)
	if err != nil {
		return err
	}
	k.queue = append(k.queue, packets...)
	return nil
}

func (k *fakeKey) Receive(context.Context) ([]byte, error) {
	if len(k.queue) == 0 {
		return nil, errors.New("fake key: nothing to say")
	}
	p := k.queue[0]
	k.queue = k.queue[1:]
	return p, nil
}

func open(t *testing.T, k *fakeKey) adminclient.FIDOSigner {
	t.Helper()
	key, err := fido.Open(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	return adminclient.FIDOSigner{Key: key}
}

func ctapReply(t *testing.T, m map[uint64]any) []byte {
	t.Helper()
	b, err := cbor.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte{0}, b...)
}

// noCredentials is CTAP2_ERR_NO_CREDENTIALS.
var noCredentials = []byte{0x2E}

func TestFIDOSignerAssert(t *testing.T) {
	var aaguid [16]byte
	auth := fidotest.New(aaguid)
	cdh := [32]byte{1, 2, 3}
	if _, _, _, err := auth.Make(context.Background(), "forge.test", nil, "n", cdh); err != nil {
		t.Fatal(err)
	}
	ad, sig, err := auth.Assert(context.Background(), "forge.test", auth.CredID, cdh)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("ok", func(t *testing.T) {
		k := newFakeKey(func(byte, []byte) []byte { return ctapReply(t, map[uint64]any{2: ad, 3: sig}) })
		gotAD, gotSig, err := open(t, k).Assert(context.Background(), "forge.test", auth.CredID, cdh)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotAD, ad) || !bytes.Equal(gotSig, sig) {
			t.Fatal("the key's assertion was not returned as is")
		}
		if k.cmd != 0x02 {
			t.Fatalf("command %#x, want getAssertion", k.cmd)
		}
		var req map[uint64]cbor.RawMessage
		if err := cbor.Unmarshal(k.got, &req); err != nil {
			t.Fatal(err)
		}
		var rp string
		var hash []byte
		var opts map[string]bool
		var allow []struct {
			Type string `cbor:"type"`
			ID   []byte `cbor:"id"`
		}
		for key, dst := range map[uint64]any{1: &rp, 2: &hash, 3: &allow, 5: &opts} {
			if err := cbor.Unmarshal(req[key], dst); err != nil {
				t.Fatalf("field %d: %v", key, err)
			}
		}
		if rp != "forge.test" || !bytes.Equal(hash, cdh[:]) || !opts["uv"] ||
			len(allow) != 1 || allow[0].Type != "public-key" || !bytes.Equal(allow[0].ID, auth.CredID) {
			t.Fatalf("request rp=%q hash=%x opts=%v allow=%v", rp, hash, opts, allow)
		}
	})
	t.Run("the key refuses", func(t *testing.T) {
		k := newFakeKey(func(byte, []byte) []byte { return noCredentials })
		gotAD, gotSig, err := open(t, k).Assert(context.Background(), "forge.test", auth.CredID, cdh)
		if err == nil || gotAD != nil || gotSig != nil {
			t.Fatalf("got %x %x %v", gotAD, gotSig, err)
		}
	})
}

func TestFIDOSignerMake(t *testing.T) {
	var aaguid [16]byte
	auth := fidotest.New(aaguid)
	cdh := [32]byte{9}
	format, ad, stmt, err := auth.Make(context.Background(), "forge.test", []byte("uh"), "laptop", cdh)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("ok", func(t *testing.T) {
		k := newFakeKey(func(byte, []byte) []byte {
			return ctapReply(t, map[uint64]any{1: format, 2: ad, 3: cbor.RawMessage(stmt)})
		})
		gotF, gotAD, gotStmt, err := open(t, k).Make(context.Background(), "forge.test", []byte("uh"), "laptop", cdh)
		if err != nil {
			t.Fatal(err)
		}
		if gotF != format || !bytes.Equal(gotAD, ad) || !bytes.Equal(gotStmt, stmt) {
			t.Fatal("the key's attestation was not returned as is")
		}
		if k.cmd != 0x01 {
			t.Fatalf("command %#x, want makeCredential", k.cmd)
		}
		var req map[uint64]cbor.RawMessage
		if err := cbor.Unmarshal(k.got, &req); err != nil {
			t.Fatal(err)
		}
		var opts map[string]bool
		var hash []byte
		var rp struct {
			ID   string `cbor:"id"`
			Name string `cbor:"name"`
		}
		var user struct {
			ID          []byte `cbor:"id"`
			Name        string `cbor:"name"`
			DisplayName string `cbor:"displayName"`
		}
		for key, dst := range map[uint64]any{1: &hash, 2: &rp, 3: &user, 7: &opts} {
			if err := cbor.Unmarshal(req[key], dst); err != nil {
				t.Fatalf("field %d: %v", key, err)
			}
		}
		if !bytes.Equal(hash, cdh[:]) || rp.ID != "forge.test" || user.Name != "laptop" || !bytes.Equal(user.ID, []byte("uh")) ||
			!opts["uv"] || opts["rk"] {
			t.Fatalf("request hash=%x rp=%+v user=%+v opts=%v", hash, rp, user, opts)
		}
	})
	t.Run("the key refuses", func(t *testing.T) {
		k := newFakeKey(func(byte, []byte) []byte { return noCredentials })
		f, gotAD, gotStmt, err := open(t, k).Make(context.Background(), "forge.test", []byte("uh"), "laptop", cdh)
		if err == nil || f != "" || gotAD != nil || gotStmt != nil {
			t.Fatalf("got %q %x %x %v", f, gotAD, gotStmt, err)
		}
	})
	t.Run("no attestation statement", func(t *testing.T) {
		k := newFakeKey(func(byte, []byte) []byte { return ctapReply(t, map[uint64]any{1: "none", 2: ad}) })
		f, gotAD, gotStmt, err := open(t, k).Make(context.Background(), "forge.test", []byte("uh"), "laptop", cdh)
		if err == nil || !strings.Contains(err.Error(), "no attestation statement") || f != "" || gotAD != nil || gotStmt != nil {
			t.Fatalf("got %q %x %x %v", f, gotAD, gotStmt, err)
		}
	})
}
