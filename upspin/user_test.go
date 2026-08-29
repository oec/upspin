// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package upspin

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestUserJSONOmitsEmptyAttestation guards the encoding of a user record
// without an attestation. The key server stores records as JSON and publishes
// a transaction log whose hashes chain over those bytes, so a record that
// gains a field encodes differently and every hash after it changes. A record
// without an attestation must encode exactly as it did before the field
// existed.
func TestUserJSONOmitsEmptyAttestation(t *testing.T) {
	u := User{
		Name:      "ann@example.com",
		Dirs:      []Endpoint{{Transport: Remote, NetAddr: "dir.example.com:443"}},
		Stores:    []Endpoint{{Transport: Remote, NetAddr: "store.example.com:443"}},
		PublicKey: PublicKey("p256\n1234\n5678\n"),
	}
	b, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(b), "Attestation") {
		t.Errorf("a record with no attestation encoded it anyway:\n%s", b)
	}

	// One that has an attestation must of course carry it.
	u.Attestation = []byte("name: ann@example.com\n---\nsignature: aa-bb\n")
	b, err = json.Marshal(u)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(b), "Attestation") {
		t.Errorf("a record with an attestation did not encode it:\n%s", b)
	}
	var got User
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if string(got.Attestation) != string(u.Attestation) {
		t.Errorf("attestation = %q; want %q", got.Attestation, u.Attestation)
	}
}
