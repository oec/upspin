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

	"upspin.io/errors"
	"upspin.io/factotum"
	"upspin.io/upspin"
)

// Key pairs, from factotum's own test data.
const (
	annSecret = "33732563467898584041325590158539299810645722675081856412396066039103123277092\n"
	bobSecret = "73412709577437621283953284627141522517131750837511539431619352194608555895350\n"
)

// rootFactotum returns a factotum holding annKey, standing for the holder of a
// domain's trusted root, and the matching public key.
func rootFactotum(t *testing.T) (upspin.Factotum, upspin.PublicKey) {
	t.Helper()
	f, err := factotum.NewFromKeys([]byte(annKey), []byte(annSecret), nil)
	if err != nil {
		t.Fatalf("NewFromKeys: %v", err)
	}
	return f, annKey
}

// otherFactotum returns a factotum for a key that is not any domain's root.
func otherFactotum(t *testing.T) upspin.Factotum {
	t.Helper()
	f, err := factotum.NewFromKeys([]byte(bobKey), []byte(bobSecret), nil)
	if err != nil {
		t.Fatalf("NewFromKeys: %v", err)
	}
	return f
}

// attestedUser is the record a root attests to: some other user in its domain.
func attestedUser() *upspin.User {
	u := annUser()
	u.Name = "carol@example.com"
	u.PublicKey = bobKey
	return u
}

func TestSignVerify(t *testing.T) {
	f, key := rootFactotum(t)
	want := attestedUser()

	data, err := Sign(f, want)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// The attested record is the plain record with a signature appended,
	// so it stays legible and can be edited by hand up to the marker.
	if !bytes.HasPrefix(data, []byte("name: carol@example.com\n")) {
		t.Errorf("attested record does not begin with the record:\n%s", data)
	}
	if !strings.Contains(string(data), "\n---\nsignature: ") {
		t.Errorf("attested record has no signature trailer:\n%s", data)
	}

	got, err := Verify(data, key)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Name != want.Name || got.PublicKey != want.PublicKey {
		t.Errorf("Verify = %+v; want %+v", got, want)
	}
}

func TestVerifyRejects(t *testing.T) {
	f, key := rootFactotum(t)
	data, err := Sign(f, attestedUser())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong key", func(t *testing.T) {
		if _, err := Verify(data, bobKey); err == nil {
			t.Error("Verify succeeded under the wrong key")
		}
	})

	t.Run("signed by a non-root", func(t *testing.T) {
		other, err := Sign(otherFactotum(t), attestedUser())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(other, key); err == nil {
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
		if _, err := Verify(tampered, key); err == nil {
			t.Error("Verify accepted a record whose public key was replaced")
		}
	})

	t.Run("substituted name", func(t *testing.T) {
		tampered := bytes.Replace(data, []byte("carol@example.com"), []byte("dave@example.com"), 1)
		if _, err := Verify(tampered, key); err == nil {
			t.Error("Verify accepted a record whose name was replaced")
		}
	})

	t.Run("no attestation", func(t *testing.T) {
		record, _, err := Split(data)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(record, key); err == nil {
			t.Error("Verify accepted a record with no attestation")
		}
	})
}

func TestSplit(t *testing.T) {
	// A record with no attestation is returned whole, with no signature
	// and no error: it is simply one that must be trusted another way.
	plain := []byte("name: ann@example.com\npublickey: |\n  p256\n")
	record, sig, err := Split(plain)
	if err != nil || sig != nil || !bytes.Equal(record, plain) {
		t.Errorf("Split(plain) = %q, %v, %v; want the input, nil, nil", record, sig, err)
	}

	for _, test := range []struct{ name, data string }{
		{"empty trailer", "name: a@b.com\n---\n"},
		{"no signature key", "name: a@b.com\n---\nsomethingelse: 1\n"},
		{"one field", "name: a@b.com\n---\nsignature: abcdef\n"},
		{"bad R", "name: a@b.com\n---\nsignature: zz-ff\n"},
		{"bad S", "name: a@b.com\n---\nsignature: ff-zz\n"},
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
	if _, sig, err := Split(notMarker); err != nil || sig != nil {
		t.Errorf("Split found an attestation in %q", notMarker)
	}
}

func TestAcceptUsesPinnedRoot(t *testing.T) {
	dir := t.TempDir()
	f, key := rootFactotum(t)

	root := annUser() // ann@example.com, holding annKey
	if root.PublicKey != key {
		t.Fatal("test setup: root record does not hold the root key")
	}
	data, err := Sign(f, attestedUser()) // carol@example.com
	if err != nil {
		t.Fatal(err)
	}

	// With no root pinned there is nothing to check the signature
	// against, so the record must be refused.
	if _, err := Accept(dir, data); err == nil {
		t.Error("Accept succeeded with no trusted root pinned")
	}

	if err := WriteRoot(dir, "example.com", root); err != nil {
		t.Fatalf("WriteRoot: %v", err)
	}
	got, err := Accept(dir, data)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got.Name != "carol@example.com" {
		t.Errorf("Accept = %q; want carol@example.com", got.Name)
	}

	// A root speaks only for the domain it is pinned under. The same
	// record, offered for a user in another domain, has no root.
	other := attestedUser()
	other.Name = "carol@example.org"
	otherData, err := Sign(f, other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Accept(dir, otherData); err == nil {
		t.Error("Accept succeeded for a domain with no pinned root")
	}

	// A root pinned for that other domain must still not accept a
	// signature made by a different key.
	elsewhere := annUser()
	elsewhere.Name = "admin@example.org"
	elsewhere.PublicKey = bobKey
	if err := WriteRoot(dir, "example.org", elsewhere); err != nil {
		t.Fatal(err)
	}
	if _, err := Accept(dir, otherData); err == nil {
		t.Error("Accept succeeded under a root that did not sign the record")
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

func TestRoots(t *testing.T) {
	dir := t.TempDir()

	if _, err := ReadRoot(dir, "example.com"); !errors.Is(errors.NotExist, err) {
		t.Errorf("ReadRoot of absent root = %v; want NotExist", err)
	}
	if got, err := ListRoots(dir); err != nil || got != nil {
		t.Errorf("ListRoots of absent directory = %v, %v; want nil, nil", got, err)
	}

	root := annUser()
	if err := WriteRoot(dir, "example.com", root); err != nil {
		t.Fatalf("WriteRoot: %v", err)
	}
	// A root is pinned for a domain, so the domain names the file.
	if _, err := os.Stat(filepath.Join(dir, RootsDir, "example.com")); err != nil {
		t.Errorf("root not stored under the domain: %v", err)
	}
	// Roots live in a subdirectory, so they are not mistaken for users.
	names, err := List(dir)
	if err != nil || names != nil {
		t.Errorf("List = %v, %v; roots must not appear as pinned users", names, err)
	}

	other := annUser()
	other.Name = "admin@example.org"
	if err := WriteRoot(dir, "example.org", other); err != nil {
		t.Fatal(err)
	}
	domains, err := ListRoots(dir)
	if err != nil {
		t.Fatalf("ListRoots: %v", err)
	}
	if len(domains) != 2 || domains[0] != "example.com" || domains[1] != "example.org" {
		t.Errorf("ListRoots = %v; want [example.com example.org]", domains)
	}

	got, err := ReadRoot(dir, "example.com")
	if err != nil {
		t.Fatalf("ReadRoot: %v", err)
	}
	if got.Name != root.Name {
		t.Errorf("ReadRoot = %q; want %q", got.Name, root.Name)
	}
	// The domain is matched case-insensitively, as user names are.
	if _, err := ReadRoot(dir, "EXAMPLE.com"); err != nil {
		t.Errorf("ReadRoot with uppercase domain: %v", err)
	}

	if err := RemoveRoot(dir, "example.com"); err != nil {
		t.Fatalf("RemoveRoot: %v", err)
	}
	if _, err := ReadRoot(dir, "example.com"); !errors.Is(errors.NotExist, err) {
		t.Errorf("ReadRoot after RemoveRoot = %v; want NotExist", err)
	}
}

// TestRootTraversal checks that a hostile domain cannot escape the roots
// directory, since the domain becomes part of a file name.
func TestRootTraversal(t *testing.T) {
	dir := t.TempDir()
	for _, domain := range []string{"../../etc/passwd", "a/b.com", "..", ""} {
		if _, err := ReadRoot(dir, domain); err == nil {
			t.Errorf("ReadRoot(%q) succeeded; want error", domain)
		} else if errors.Is(errors.IO, err) {
			t.Errorf("ReadRoot(%q) reached the file system: %v", domain, err)
		}
	}
}

// TestReadAttested checks that an attested record works as a pinned record:
// Read parses past the signature, since what is in the key directory is
// trusted because it is there.
func TestReadAttested(t *testing.T) {
	dir := t.TempDir()
	f, _ := rootFactotum(t)
	want := attestedUser()
	data, err := Sign(f, want)
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
