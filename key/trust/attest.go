// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trust

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	yaml "gopkg.in/yaml.v2"

	"upspin.io/errors"
	"upspin.io/factotum"
	"upspin.io/upspin"
	"upspin.io/user"
)

// An attested record is the YAML encoding of an upspin.User followed by a
// signature over it, separated by a YAML document marker:
//
//	name: alice@example.com
//	dirs:
//	- remote,dir.example.com:443
//	stores:
//	- remote,store.example.com:443
//	publickey: |
//	  p256
//	  1234...
//	  5678...
//	---
//	signature: a1b2c3...-d4e5f6...
//
// The signature is made by a trust anchor: a key that the reader has pinned
// as entitled to speak for a domain, held in the trust-anchors subdirectory
// of the key directory. It covers the record bytes exactly as they appear in
// the file, so there is no question of canonical encoding, and it is prefixed
// with a label so that it cannot be confused with a signature made over
// something else.
//
// An attested record needs no separate verification by the reader: whoever
// holds the anchor key for a domain vouches for every user in it. Pinning one
// key per domain is therefore enough to accept records for all its users.

// AnchorsDir is the subdirectory of the key directory that holds trust anchors,
// one file per domain, named for the domain and holding the upspin.User
// record of the user entitled to attest for it.
const AnchorsDir = "trust-anchors"

// separator marks the end of the record and the start of the signature. It is
// also a YAML document marker, so an attested record is a valid YAML stream.
const separator = "---"

// signatureLabel prefixes the signed bytes, so that a signature over a user
// record cannot be mistaken for a signature over anything else.
const signatureLabel = "upspin-user-record:"

// signature is the YAML form of the trailer of an attested record.
type signature struct {
	Signature string `yaml:"signature"`
}

// hashRecord returns the hash that an attestation over record signs.
func hashRecord(record []byte) []byte {
	h := sha256.New()
	h.Write([]byte(signatureLabel))
	h.Write(record)
	return h.Sum(nil)
}

// Split separates an attested record into the record bytes that are signed and
// the signature over them. If data carries no attestation it returns the whole
// of data and a nil signature, which is not an error: an unattested record is
// merely one that must be trusted some other way.
func Split(data []byte) ([]byte, *upspin.Signature, error) {
	const op errors.Op = "key/trust.Split"

	// The marker is a line of its own; find it without disturbing the
	// bytes before it, which are what the signature covers.
	record, trailer, ok := cutLine(data, separator)
	if !ok {
		return data, nil, nil
	}
	var s signature
	if err := yaml.Unmarshal(trailer, &s); err != nil {
		return nil, nil, errors.E(op, errors.Invalid, errors.Errorf("parsing signature: %v", err))
	}
	if s.Signature == "" {
		return nil, nil, errors.E(op, errors.Invalid, "no signature after the document marker")
	}
	fields := strings.Split(s.Signature, "-")
	if len(fields) != 2 {
		return nil, nil, errors.E(op, errors.Invalid, "malformed signature")
	}
	var r, ss big.Int
	if _, ok := r.SetString(fields[0], 16); !ok {
		return nil, nil, errors.E(op, errors.Invalid, "malformed signature: bad R")
	}
	if _, ok := ss.SetString(fields[1], 16); !ok {
		return nil, nil, errors.E(op, errors.Invalid, "malformed signature: bad S")
	}
	return record, &upspin.Signature{R: &r, S: &ss}, nil
}

// cutLine splits data at the first line equal to line, returning the bytes
// before it, the bytes after it, and whether it was found.
func cutLine(data []byte, line string) (before, after []byte, ok bool) {
	want := []byte(line + "\n")
	for i := 0; i < len(data); {
		end := bytes.IndexByte(data[i:], '\n')
		if end < 0 {
			// The final line, with no newline: compare it whole.
			if string(data[i:]) == line {
				return data[:i], nil, true
			}
			return nil, nil, false
		}
		end += i + 1
		if bytes.Equal(data[i:end], want) {
			return data[:i], data[end:], true
		}
		i = end
	}
	return nil, nil, false
}

// Sign returns an attested record for u, signed with f, which must be the
// factotum of the user that readers pin as the trust anchor for u's domain.
func Sign(f upspin.Factotum, u *upspin.User) ([]byte, error) {
	const op errors.Op = "key/trust.Sign"
	if f == nil {
		return nil, errors.E(op, errors.Invalid, "no factotum")
	}
	if err := Validate(u); err != nil {
		return nil, errors.E(op, err)
	}
	record, err := yaml.Marshal(*u)
	if err != nil {
		return nil, errors.E(op, u.Name, err)
	}
	sig, err := f.Sign(hashRecord(record))
	if err != nil {
		return nil, errors.E(op, u.Name, err)
	}
	var b bytes.Buffer
	b.Write(record)
	fmt.Fprintf(&b, "%s\nsignature: %x-%x\n", separator, sig.R, sig.S)
	return b.Bytes(), nil
}

// Verify checks the attestation in data against key and returns the record it
// attests to, with the attestation carried on it. It fails if data carries no
// attestation.
func Verify(data []byte, key upspin.PublicKey) (*upspin.User, error) {
	const op errors.Op = "key/trust.Verify"
	record, sig, err := Split(data)
	if err != nil {
		return nil, errors.E(op, err)
	}
	if sig == nil {
		return nil, errors.E(op, errors.Invalid, "record carries no attestation")
	}
	if err := factotum.Verify(hashRecord(record), *sig, key); err != nil {
		return nil, errors.E(op, errors.Invalid, errors.Errorf("attestation does not verify: %v", err))
	}
	u := new(upspin.User)
	if err := yaml.Unmarshal(record, u); err != nil {
		return nil, errors.E(op, errors.Invalid, errors.Errorf("parsing attested record: %v", err))
	}
	if err := Validate(u); err != nil {
		return nil, errors.E(op, err)
	}
	// Carry the attestation on the record it vouches for. It is not part
	// of what the signature covers, and so is not in the parsed record,
	// but a record that arrived with evidence should keep it: whoever
	// receives it next can check it too, or pass it on.
	u.Attestation = data
	return u, nil
}

// Accept verifies an attested record against the trust anchors pinned in dir
// and returns the record. It is the check to apply to a record that arrives
// from somewhere the reader does not control. It fails if the record carries
// no attestation, if no anchor is pinned for the record's domain, or if the
// signature does not verify under that anchor.
//
// The first two failures are of kind errors.NotExist and mean only that the
// record cannot be believed on its own account; the caller may still have some
// other reason to accept it. Any other failure means the record was offered
// with a signature that does not hold, and should be treated as hostile.
func Accept(dir string, data []byte) (*upspin.User, error) {
	const op errors.Op = "key/trust.Accept"
	record, sig, err := Split(data)
	if err != nil {
		return nil, errors.E(op, err)
	}
	if sig == nil {
		return nil, errors.E(op, errors.NotExist, "record carries no attestation")
	}
	// Read the name first, to learn which anchor should have signed it. The
	// record is not trusted until the signature has been checked; nothing
	// is taken from it here but the domain.
	u := new(upspin.User)
	if err := yaml.Unmarshal(record, u); err != nil {
		return nil, errors.E(op, errors.Invalid, errors.Errorf("parsing attested record: %v", err))
	}
	domain, err := domainOf(u.Name)
	if err != nil {
		return nil, errors.E(op, err)
	}
	anchor, err := ReadAnchor(dir, domain)
	if err != nil {
		// Keep the NotExist kind, so that a caller can tell "no anchor
		// is pinned for this domain", which is ordinary, from "the
		// signature does not verify", which is not.
		return nil, errors.E(op, errors.NotExist,
			errors.Errorf("no trust anchor for %s: %v", domain, err))
	}
	attested, err := Verify(data, anchor.PublicKey)
	if err != nil {
		return nil, errors.E(op, err)
	}
	// The signature covers the name, so this cannot differ from the domain
	// checked above, but say so rather than rely on that.
	if got, _ := domainOf(attested.Name); got != domain {
		return nil, errors.E(op, errors.Invalid, "attested name does not match")
	}
	return attested, nil
}

// domainOf returns the domain component of a user name.
func domainOf(name upspin.UserName) (string, error) {
	_, _, domain, err := user.Parse(name)
	if err != nil {
		return "", err
	}
	return domain, nil
}

// anchorFileName returns the name of the file holding the trust anchor for
// domain, within dir.
func anchorFileName(op errors.Op, dir, domain string) (string, error) {
	// A domain is validated by user.Parse as part of a user name; check it
	// that way rather than trusting a bare string that is about to become
	// a file name.
	if _, _, _, err := user.Parse(upspin.UserName("anyone@" + domain)); err != nil {
		return "", errors.E(op, errors.Invalid, errors.Errorf("%q is not a valid domain: %v", domain, err))
	}
	domain = strings.ToLower(domain)
	if filepath.Base(domain) != domain {
		return "", errors.E(op, errors.Invalid, "domain is not a valid file name")
	}
	return filepath.Join(dir, AnchorsDir, domain), nil
}

// ReadAnchor returns the trust anchor pinned for domain in dir. If there is
// none it returns an error of kind errors.NotExist.
func ReadAnchor(dir, domain string) (*upspin.User, error) {
	const op errors.Op = "key/trust.ReadAnchor"
	file, err := anchorFileName(op, dir, domain)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return nil, errors.E(op, errors.NotExist, errors.Errorf("no trust anchor for %s", domain))
	}
	if err != nil {
		return nil, errors.E(op, errors.IO, err)
	}
	u := new(upspin.User)
	if err := yaml.Unmarshal(data, u); err != nil {
		return nil, errors.E(op, errors.Invalid, errors.Errorf("parsing %s: %v", file, err))
	}
	if err := Validate(u); err != nil {
		return nil, errors.E(op, errors.Errorf("%s: %v", file, err))
	}
	return u, nil
}

// WriteAnchor pins u as the trust anchor for domain in dir, replacing any anchor
// already pinned for it.
func WriteAnchor(dir, domain string, u *upspin.User) error {
	const op errors.Op = "key/trust.WriteAnchor"
	if err := Validate(u); err != nil {
		return errors.E(op, err)
	}
	file, err := anchorFileName(op, dir, domain)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(*u)
	if err != nil {
		return errors.E(op, u.Name, err)
	}
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return errors.E(op, errors.IO, err)
	}
	if err := os.WriteFile(file, data, 0600); err != nil {
		return errors.E(op, errors.IO, err)
	}
	return nil
}

// RemoveAnchor deletes the trust anchor pinned for domain in dir.
func RemoveAnchor(dir, domain string) error {
	const op errors.Op = "key/trust.RemoveAnchor"
	file, err := anchorFileName(op, dir, domain)
	if err != nil {
		return err
	}
	if err := os.Remove(file); err != nil {
		if os.IsNotExist(err) {
			return errors.E(op, errors.NotExist, errors.Errorf("no trust anchor for %s", domain))
		}
		return errors.E(op, errors.IO, err)
	}
	return nil
}

// ListAnchors returns the domains for which a trust anchor is pinned in dir,
// sorted. A directory that does not exist holds no anchors and is not an error.
func ListAnchors(dir string) ([]string, error) {
	const op errors.Op = "key/trust.ListAnchors"
	entries, err := os.ReadDir(filepath.Join(dir, AnchorsDir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.E(op, errors.IO, err)
	}
	var domains []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if _, _, _, err := user.Parse(upspin.UserName("anyone@" + e.Name())); err != nil {
			// Not a domain; not ours.
			continue
		}
		domains = append(domains, e.Name())
	}
	return domains, nil
}
