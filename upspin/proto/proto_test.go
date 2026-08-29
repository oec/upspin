// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proto

import (
	"bytes"
	"testing"

	pb "github.com/golang/protobuf/proto"

	"upspin.io/upspin"
)

// TestUserAttestation checks that a user record's attestation survives the
// wire. The field must be in the message descriptor and not merely in the Go
// struct: the encoding is driven by the descriptor, so a field missing from it
// is dropped in silence, and a key server would appear to answer without one.
func TestUserAttestation(t *testing.T) {
	attestation := []byte("name: ann@example.com\n---\nsignature: aabb-ccdd\n")
	want := &upspin.User{
		Name:        "ann@example.com",
		Dirs:        []upspin.Endpoint{{Transport: upspin.Remote, NetAddr: "dir.example.com:443"}},
		Stores:      []upspin.Endpoint{{Transport: upspin.Remote, NetAddr: "store.example.com:443"}},
		PublicKey:   upspin.PublicKey("p256\n1234\n5678\n"),
		Attestation: attestation,
	}

	data, err := pb.Marshal(UserProto(want))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var wire User
	if err := pb.Unmarshal(data, &wire); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	got := UpspinUser(&wire)

	if !bytes.Equal(got.Attestation, attestation) {
		t.Errorf("attestation = %q; want %q", got.Attestation, attestation)
	}
	if got.Name != want.Name || got.PublicKey != want.PublicKey {
		t.Errorf("record = %+v; want %+v", got, want)
	}
	if len(got.Dirs) != 1 || got.Dirs[0] != want.Dirs[0] {
		t.Errorf("dirs = %v; want %v", got.Dirs, want.Dirs)
	}
	if len(got.Stores) != 1 || got.Stores[0] != want.Stores[0] {
		t.Errorf("stores = %v; want %v", got.Stores, want.Stores)
	}

	// A record without one must not grow an empty attestation, so that
	// "has an attestation" stays a meaningful question.
	want.Attestation = nil
	data, err = pb.Marshal(UserProto(want))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	wire = User{}
	if err := pb.Unmarshal(data, &wire); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got := UpspinUser(&wire); len(got.Attestation) != 0 {
		t.Errorf("attestation = %q; want none", got.Attestation)
	}
}

// TestUserAttestationIsInDescriptor states the same requirement directly, so
// that a regenerated upspin.pb.go that lost the field fails here with a clear
// reason rather than through a puzzling absence elsewhere.
func TestUserAttestationIsInDescriptor(t *testing.T) {
	fields := pb.MessageV2(&User{}).ProtoReflect().Descriptor().Fields()
	f := fields.ByName("attestation")
	if f == nil {
		t.Fatal("message User has no attestation field; was upspin.pb.go regenerated from a stale upspin.proto?")
	}
	if got, want := int(f.Number()), 5; got != want {
		t.Errorf("attestation field number = %d; want %d", got, want)
	}
	if got, want := f.Kind().String(), "bytes"; got != want {
		t.Errorf("attestation field kind = %s; want %s", got, want)
	}
}
