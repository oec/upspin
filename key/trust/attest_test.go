// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trust

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v2"

	"upspin.io/errors"
	"upspin.io/factotum"
	"upspin.io/upspin"
)

// Key pairs, from factotum's own test data.
const (
	annSecret = "33732563467898584041325590158539299810645722675081856412396066039103123277092\n"
	bobSecret = "73412709577437621283953284627141522517131750837511539431619352194608555895350\n"
)

// anchorFactotum returns a factotum holding annKey, standing for the holder of a
// domain's trust anchor, and the matching public key.
func anchorFactotum(t *testing.T) (upspin.Factotum, upspin.PublicKey) {
	t.Helper()
	f, err := factotum.NewFromKeys([]byte(annKey), []byte(annSecret), nil)
	if err != nil {
		t.Fatalf("NewFromKeys: %v", err)
	}
	return f, annKey
}

// otherFactotum returns a factotum for a key that is not any domain's trust anchor.
func otherFactotum(t *testing.T) upspin.Factotum {
	t.Helper()
	f, err := factotum.NewFromKeys([]byte(bobKey), []byte(bobSecret), nil)
	if err != nil {
		t.Fatalf("NewFromKeys: %v", err)
	}
	return f
}

// The names of the two signing identities above. A signature names its signer,
// so the tests must say who is signing as well as with which key.
const (
	anchorName = upspin.UserName("ann@example.com")
	otherName  = upspin.UserName("bob@example.com")
)

// attestedUser is the record an anchor attests to: some other user in its domain.
func attestedUser() *upspin.User {
	u := annUser()
	u.Name = "carol@example.com"
	u.PublicKey = bobKey
	return u
}

func TestSignVerify(t *testing.T) {
	f, key := anchorFactotum(t)
	want := attestedUser()

	data, err := Sign(f, anchorName, want)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// The attested record is the plain record with a signature appended,
	// so it stays legible and can be edited by hand up to the marker.
	if !bytes.HasPrefix(data, []byte("name: carol@example.com\n")) {
		t.Errorf("attested record does not begin with the record:\n%s", data)
	}
	if !strings.Contains(string(data), "\n---\nsignatures:\n") {
		t.Errorf("attested record has no signature trailer:\n%s", data)
	}
	// The signer is named, so that a reader can tell which anchor to check
	// the record against without trying every one they hold.
	if !strings.Contains(string(data), "signer: "+string(anchorName)+"\n") {
		t.Errorf("attested record does not name its signer:\n%s", data)
	}

	got, err := Verify(data, anchorName, key)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Name != want.Name || got.PublicKey != want.PublicKey {
		t.Errorf("Verify = %+v; want %+v", got, want)
	}
}

func TestVerifyRejects(t *testing.T) {
	f, key := anchorFactotum(t)
	data, err := Sign(f, anchorName, attestedUser())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong key", func(t *testing.T) {
		if _, err := Verify(data, anchorName, bobKey); err == nil {
			t.Error("Verify succeeded under the wrong key")
		}
	})

	t.Run("signed by a non-anchor", func(t *testing.T) {
		other, err := Sign(otherFactotum(t), otherName, attestedUser())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(other, otherName, key); err == nil {
			t.Error("Verify succeeded for a record signed by another key")
		}
	})

	// Substituting the public key is the whole attack an attestation
	// exists to stop, so check that specifically as well as generally.
	t.Run("substituted public key", func(t *testing.T) {
		// The key is written as an indented YAML block, so swap the
		// first coordinate rather than the whole rendered key.
		from := []byte(strings.Split(string(bobKey), "\n")[1])
		to := []byte(strings.Split(string(annKey), "\n")[1])
		tampered := bytes.Replace(data, from, to, 1)
		if bytes.Equal(tampered, data) {
			t.Fatal("test did not modify the record")
		}
		if _, err := Verify(tampered, anchorName, key); err == nil {
			t.Error("Verify accepted a record whose public key was replaced")
		}
	})

	t.Run("substituted name", func(t *testing.T) {
		tampered := bytes.Replace(data, []byte("carol@example.com"), []byte("dave@example.com"), 1)
		if _, err := Verify(tampered, anchorName, key); err == nil {
			t.Error("Verify accepted a record whose name was replaced")
		}
	})

	t.Run("no attestation", func(t *testing.T) {
		record, _, err := Split(data)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(record, anchorName, key); err == nil {
			t.Error("Verify accepted a record with no attestation")
		}
	})
}

func TestSplit(t *testing.T) {
	// A record with no attestation is returned whole, with no signature
	// and no error: it is simply one that must be trusted another way.
	plain := []byte("name: ann@example.com\npublickey: |\n  p256\n")
	record, sigs, err := Split(plain)
	if err != nil || len(sigs) != 0 || !bytes.Equal(record, plain) {
		t.Errorf("Split(plain) = %q, %v, %v; want the input, none, nil", record, sigs, err)
	}

	for _, test := range []struct{ name, data string }{
		{"empty trailer", "name: a@b.com\n---\n"},
		{"no signatures key", "name: a@b.com\n---\nsomethingelse: 1\n"},
		{"empty list", "name: a@b.com\n---\nsignatures:\n"},
		{"one field", "name: a@b.com\n---\nsignatures:\n- signer: a@b.com\n  signature: abcdef\n"},
		{"bad R", "name: a@b.com\n---\nsignatures:\n- signer: a@b.com\n  signature: zz-ff\n"},
		{"bad S", "name: a@b.com\n---\nsignatures:\n- signer: a@b.com\n  signature: ff-zz\n"},
		{"no signer", "name: a@b.com\n---\nsignatures:\n- signature: ff-ff\n"},
		{"signer is not a user name", "name: a@b.com\n---\nsignatures:\n- signer: nobody\n  signature: ff-ff\n"},
		{"the old single-signature form", "name: a@b.com\n---\nsignature: ff-ff\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := Split([]byte(test.data)); err == nil {
				t.Error("Split succeeded; want error")
			}
		})
	}

	// A marker must be a line of its own: a record whose text merely
	// contains the marker's characters is not attested.
	notMarker := []byte("name: a@b.com\ncomment: a---b\n")
	if _, sigs, err := Split(notMarker); err != nil || len(sigs) != 0 {
		t.Errorf("Split found an attestation in %q", notMarker)
	}
}

func TestAcceptUsesPinnedAnchor(t *testing.T) {
	dir := t.TempDir()
	f, key := anchorFactotum(t)

	anchor := annUser() // ann@example.com, holding annKey
	if anchor.PublicKey != key {
		t.Fatal("test setup: anchor record does not hold the anchor key")
	}
	data, err := Sign(f, anchorName, attestedUser()) // carol@example.com
	if err != nil {
		t.Fatal(err)
	}

	// With no anchor pinned there is nothing to check the signature
	// against, so the record must be refused.
	if _, err := Accept(dir, data); err == nil {
		t.Error("Accept succeeded with no trust anchor pinned")
	}

	if err := WriteAnchor(dir, "example.com", anchor); err != nil {
		t.Fatalf("WriteAnchor: %v", err)
	}
	got, err := Accept(dir, data)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got.Name != "carol@example.com" {
		t.Errorf("Accept = %q; want carol@example.com", got.Name)
	}

	// An anchor speaks only for the domain it is pinned under. The same
	// record, offered for a user in another domain, has no anchor.
	other := attestedUser()
	other.Name = "carol@example.org"
	otherData, err := Sign(f, anchorName, other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Accept(dir, otherData); err == nil {
		t.Error("Accept succeeded for a domain with no pinned anchor")
	}

	// An anchor pinned for that other domain must still not accept a
	// signature made by a different key.
	elsewhere := annUser()
	elsewhere.Name = "admin@example.org"
	elsewhere.PublicKey = bobKey
	if err := WriteAnchor(dir, "example.org", elsewhere); err != nil {
		t.Fatal(err)
	}
	if _, err := Accept(dir, otherData); err == nil {
		t.Error("Accept succeeded under an anchor that did not sign the record")
	}

	// An unattested record is never acceptable, however well known its
	// contents: Accept is the boundary check, and there is nothing there
	// to check.
	record, _, err := Split(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Accept(dir, record); err == nil {
		t.Error("Accept succeeded for a record with no attestation")
	}
}

func TestAnchors(t *testing.T) {
	dir := t.TempDir()

	if _, err := ReadAnchors(dir, "example.com"); !errors.Is(errors.NotExist, err) {
		t.Errorf("ReadAnchors of absent anchor = %v; want NotExist", err)
	}
	if got, err := ListAnchors(dir); err != nil || got != nil {
		t.Errorf("ListAnchors of absent directory = %v, %v; want nil, nil", got, err)
	}

	anchor := annUser()
	if err := WriteAnchor(dir, "example.com", anchor); err != nil {
		t.Fatalf("WriteAnchor: %v", err)
	}
	// A domain may have more than one anchor, so the domain names a
	// directory and each anchor within it is named for its user.
	if _, err := os.Stat(filepath.Join(dir, AnchorsDir, "example.com", string(anchor.Name))); err != nil {
		t.Errorf("anchor not stored under the domain: %v", err)
	}
	// Anchors live in a subdirectory, so they are not mistaken for users.
	names, err := List(dir)
	if err != nil || names != nil {
		t.Errorf("List = %v, %v; anchors must not appear as pinned users", names, err)
	}

	other := annUser()
	other.Name = "admin@example.org"
	if err := WriteAnchor(dir, "example.org", other); err != nil {
		t.Fatal(err)
	}
	domains, err := ListAnchors(dir)
	if err != nil {
		t.Fatalf("ListAnchors: %v", err)
	}
	if len(domains) != 2 || domains[0] != "example.com" || domains[1] != "example.org" {
		t.Errorf("ListAnchors = %v; want [example.com example.org]", domains)
	}

	got, err := ReadAnchor(dir, "example.com", anchor.Name)
	if err != nil {
		t.Fatalf("ReadAnchor: %v", err)
	}
	if got.Name != anchor.Name {
		t.Errorf("ReadAnchor = %q; want %q", got.Name, anchor.Name)
	}
	// The domain is matched case-insensitively, as user names are.
	if _, err := ReadAnchors(dir, "EXAMPLE.com"); err != nil {
		t.Errorf("ReadAnchors with uppercase domain: %v", err)
	}
	// A name that is not an anchor for the domain is absent, not an error
	// of some other kind.
	if _, err := ReadAnchor(dir, "example.com", otherName); !errors.Is(errors.NotExist, err) {
		t.Errorf("ReadAnchor of a name that is not an anchor = %v; want NotExist", err)
	}

	if err := RemoveAnchor(dir, "example.com", anchor.Name); err != nil {
		t.Fatalf("RemoveAnchor: %v", err)
	}
	if _, err := ReadAnchors(dir, "example.com"); !errors.Is(errors.NotExist, err) {
		t.Errorf("ReadAnchors after RemoveAnchor = %v; want NotExist", err)
	}
	// The domain drops out of the listing with its last anchor.
	if domains, err := ListAnchors(dir); err != nil || len(domains) != 1 || domains[0] != "example.org" {
		t.Errorf("ListAnchors = %v, %v; want [example.org], nil", domains, err)
	}
}

// TestAnchorTraversal checks that a hostile domain cannot escape the anchors
// directory, since the domain becomes part of a file name.
func TestAnchorTraversal(t *testing.T) {
	dir := t.TempDir()
	for _, domain := range []string{"../../etc/passwd", "a/b.com", "..", ""} {
		if _, err := ReadAnchors(dir, domain); err == nil {
			t.Errorf("ReadAnchors(%q) succeeded; want error", domain)
		} else if errors.Is(errors.IO, err) {
			t.Errorf("ReadAnchors(%q) reached the file system: %v", domain, err)
		}
	}
}

// TestReadAttested checks that an attested record works as a pinned record:
// Read parses past the signature, since what is in the key directory is
// trusted because it is there.
func TestReadAttested(t *testing.T) {
	dir := t.TempDir()
	f, _ := anchorFactotum(t)
	want := attestedUser()
	data, err := Sign(f, anchorName, want)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, string(want.Name)), data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Read(dir, want.Name)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.PublicKey != want.PublicKey {
		t.Errorf("Read = %q; want %q", got.PublicKey, want.PublicKey)
	}
}

// bobAnchor is a second anchor for example.com, holding bobKey, so that the
// tests can pin more than one anchor for a domain.
func bobAnchor() *upspin.User {
	u := annUser()
	u.Name = otherName
	u.PublicKey = bobKey
	return u
}

// corruptSignature returns data with the signature by signer damaged, leaving
// the entry in place and still naming signer.
func corruptSignature(t *testing.T, data []byte, signer upspin.UserName) []byte {
	t.Helper()
	marker := []byte("signer: " + string(signer) + "\n  signature: ")
	i := bytes.Index(data, marker)
	if i < 0 {
		t.Fatalf("no signature by %s in:\n%s", signer, data)
	}
	out := append([]byte(nil), data...)
	if j := i + len(marker); out[j] == '0' {
		out[j] = '1'
	} else {
		out[j] = '0'
	}
	return out
}

// TestMultipleSignatures checks that a record can carry signatures from more
// than one anchor, and that a reader accepts it on whichever of them they have
// pinned.
func TestMultipleSignatures(t *testing.T) {
	f, _ := anchorFactotum(t)

	one, err := Sign(f, anchorName, attestedUser())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	both, err := Add(one, otherFactotum(t), otherName)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	// The record is untouched; only the trailer grew.
	record, sigs, err := Split(both)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if first, _, _ := Split(one); !bytes.Equal(record, first) {
		t.Error("Add changed the record it signed")
	}
	if len(sigs) != 2 || sigs[0].Signer != anchorName || sigs[1].Signer != otherName {
		t.Fatalf("Split = %v; want signatures by %s then %s", sigs, anchorName, otherName)
	}

	// Each reader pins one anchor, and each accepts the same record.
	for _, anchor := range []*upspin.User{annUser(), bobAnchor()} {
		t.Run(string(anchor.Name), func(t *testing.T) {
			dir := t.TempDir()
			if err := WriteAnchor(dir, "example.com", anchor); err != nil {
				t.Fatal(err)
			}
			got, err := Accept(dir, both)
			if err != nil {
				t.Fatalf("Accept: %v", err)
			}
			if got.Name != "carol@example.com" {
				t.Errorf("Accept = %q; want carol@example.com", got.Name)
			}
		})
	}
}

// TestAppendedSignatureCannotDeny checks that a bad signature naming a pinned
// anchor does not cost the record its other, good signature. Anyone can append
// to a published record, so treating one bad entry as fatal would let a
// stranger deny the record to every reader.
func TestAppendedSignatureCannotDeny(t *testing.T) {
	dir := t.TempDir()
	// Pin both anchors, so that the damaged signature is one the reader
	// will actually try rather than one they skip as none of their business.
	if err := WriteAnchor(dir, "example.com", annUser()); err != nil {
		t.Fatal(err)
	}
	if err := WriteAnchor(dir, "example.com", bobAnchor()); err != nil {
		t.Fatal(err)
	}

	f, _ := anchorFactotum(t)
	// Sign as bob first, so that the damaged signature is the one Accept
	// reaches first and must get past.
	data, err := Sign(otherFactotum(t), otherName, attestedUser())
	if err != nil {
		t.Fatal(err)
	}
	if data, err = Add(data, f, anchorName); err != nil {
		t.Fatal(err)
	}
	damaged := corruptSignature(t, data, otherName)

	got, err := Accept(dir, damaged)
	if err != nil {
		t.Fatalf("Accept refused a record whose other signature is good: %v", err)
	}
	if got.Name != "carol@example.com" {
		t.Errorf("Accept = %q; want carol@example.com", got.Name)
	}
}

// TestBadSignatureFromPinnedAnchor checks the other side of that: when the
// damaged signature is the only one addressed to this reader, the record is
// refused, and refused as Invalid rather than NotExist, since something offered
// a signature that does not hold.
func TestBadSignatureFromPinnedAnchor(t *testing.T) {
	dir := t.TempDir()
	if err := WriteAnchor(dir, "example.com", annUser()); err != nil {
		t.Fatal(err)
	}
	f, _ := anchorFactotum(t)
	data, err := Sign(f, anchorName, attestedUser())
	if err != nil {
		t.Fatal(err)
	}
	_, err = Accept(dir, corruptSignature(t, data, anchorName))
	if err == nil {
		t.Fatal("Accept succeeded with a damaged signature")
	}
	if !errors.Is(errors.Invalid, err) {
		t.Errorf("Accept = %v; want Invalid", err)
	}
	if errors.Is(errors.NotExist, err) {
		t.Errorf("Accept reported a bad signature as an absent one: %v", err)
	}
}

// TestUnpinnedSignerIsSkipped checks that a signature by someone the reader has
// not pinned is not addressed to them: it is absent, not hostile.
func TestUnpinnedSignerIsSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := WriteAnchor(dir, "example.com", annUser()); err != nil {
		t.Fatal(err)
	}
	data, err := Sign(otherFactotum(t), otherName, attestedUser())
	if err != nil {
		t.Fatal(err)
	}
	_, err = Accept(dir, data)
	if err == nil {
		t.Fatal("Accept succeeded for a record signed by no pinned anchor")
	}
	if !errors.Is(errors.NotExist, err) {
		t.Errorf("Accept = %v; want NotExist", err)
	}
}

// TestSignerIsSigned checks that the signer's name is covered by the signature,
// so that a signature cannot be relabelled as coming from an anchor the reader
// has pinned.
func TestSignerIsSigned(t *testing.T) {
	data, err := Sign(otherFactotum(t), otherName, attestedUser())
	if err != nil {
		t.Fatal(err)
	}
	relabelled := bytes.Replace(data,
		[]byte("signer: "+string(otherName)),
		[]byte("signer: "+string(anchorName)), 1)
	if bytes.Equal(relabelled, data) {
		t.Fatal("test did not relabel the signature")
	}

	// It verifies under neither key: not under ann's, which did not make
	// it, and no longer under bob's, whose name it no longer covers.
	if _, err := Verify(relabelled, anchorName, annKey); err == nil {
		t.Error("Verify accepted a relabelled signature under the named key")
	}
	if _, err := Verify(relabelled, anchorName, bobKey); err == nil {
		t.Error("Verify accepted a relabelled signature under the signing key")
	}

	dir := t.TempDir()
	if err := WriteAnchor(dir, "example.com", annUser()); err != nil {
		t.Fatal(err)
	}
	if _, err := Accept(dir, relabelled); err == nil {
		t.Error("Accept took a relabelled signature for its anchor's")
	}
}

// TestAddRefusesDuplicateSigner checks that a signer cannot appear twice, which
// would leave a reader to decide which of two entries in their anchor's name to
// believe.
func TestAddRefusesDuplicateSigner(t *testing.T) {
	f, _ := anchorFactotum(t)
	data, err := Sign(f, anchorName, attestedUser())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Add(data, f, anchorName); !errors.Is(errors.Exist, err) {
		t.Errorf("Add of a second signature by the same signer = %v; want Exist", err)
	}
	// Add passes the record through untouched, so it must check it before
	// signing rather than put a signature on whatever it is handed.
	if _, err := Add([]byte("name: carol@example.com\n"), f, anchorName); err == nil {
		t.Error("Add signed a record with no public key")
	}
	// Appending to a record that carries no signature yet is signing it.
	plain, err := yaml.Marshal(*attestedUser())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Add(plain, f, anchorName)
	if err != nil {
		t.Fatalf("Add to an unattested record: %v", err)
	}
	if _, err := Verify(signed, anchorName, annKey); err != nil {
		t.Errorf("Verify of a record signed by Add: %v", err)
	}
}

// TestAnchorRotation walks the arrangement that multiple signatures exist for:
// a domain replaces its anchor key, publishes records signed by both, and its
// readers re-pin whenever they get to it rather than all at one instant.
func TestAnchorRotation(t *testing.T) {
	old, _ := anchorFactotum(t)
	// The domain signs with the outgoing key and adds the incoming one.
	published, err := Sign(old, anchorName, attestedUser())
	if err != nil {
		t.Fatal(err)
	}
	published, err = Add(published, otherFactotum(t), otherName)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := WriteAnchor(dir, "example.com", annUser()); err != nil {
		t.Fatal(err)
	}
	// A reader who has not yet heard of the rotation still accepts.
	if _, err := Accept(dir, published); err != nil {
		t.Fatalf("Accept before rotating: %v", err)
	}
	// They pin the new anchor beside the old, as they would during the
	// changeover, and still accept.
	if err := WriteAnchor(dir, "example.com", bobAnchor()); err != nil {
		t.Fatal(err)
	}
	if _, err := Accept(dir, published); err != nil {
		t.Fatalf("Accept with both anchors pinned: %v", err)
	}
	// They drop the old one, and still accept.
	if err := RemoveAnchor(dir, "example.com", anchorName); err != nil {
		t.Fatal(err)
	}
	if _, err := Accept(dir, published); err != nil {
		t.Fatalf("Accept after rotating: %v", err)
	}
}

// TestAnchorMigration checks that a domain whose anchor was pinned as a single
// file, the layout before a domain could have more than one, keeps working and
// is converted when a second anchor is added.
func TestAnchorMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, AnchorsDir, "example.com")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	data, err := yaml.Marshal(*annUser())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	// The old layout is read as the one anchor it holds.
	anchors, err := ReadAnchors(dir, "example.com")
	if err != nil {
		t.Fatalf("ReadAnchors of the single-file form: %v", err)
	}
	if len(anchors) != 1 || anchors[0].Name != anchorName {
		t.Fatalf("ReadAnchors = %v; want one anchor for %s", anchors, anchorName)
	}
	if domains, err := ListAnchors(dir); err != nil || len(domains) != 1 {
		t.Errorf("ListAnchors = %v, %v; want [example.com], nil", domains, err)
	}
	// A record signed by it is accepted, so the old layout is not merely
	// readable but usable.
	f, _ := anchorFactotum(t)
	signed, err := Sign(f, anchorName, attestedUser())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Accept(dir, signed); err != nil {
		t.Errorf("Accept under a single-file anchor: %v", err)
	}

	// Adding a second anchor converts it, keeping the first.
	if err := WriteAnchor(dir, "example.com", bobAnchor()); err != nil {
		t.Fatalf("WriteAnchor: %v", err)
	}
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		t.Fatalf("anchor path was not converted to a directory: %v", err)
	}
	anchors, err = ReadAnchors(dir, "example.com")
	if err != nil {
		t.Fatalf("ReadAnchors after migrating: %v", err)
	}
	if len(anchors) != 2 || anchors[0].Name != anchorName || anchors[1].Name != otherName {
		t.Errorf("ReadAnchors = %v; want anchors for %s and %s", anchors, anchorName, otherName)
	}
	if _, err := Accept(dir, signed); err != nil {
		t.Errorf("Accept after migrating: %v", err)
	}
}
