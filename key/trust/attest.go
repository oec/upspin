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
	"sort"
	"strings"

	yaml "gopkg.in/yaml.v2"

	"upspin.io/errors"
	"upspin.io/factotum"
	"upspin.io/upspin"
	"upspin.io/user"
)

// An attested record is the YAML encoding of an upspin.User followed by the
// signatures made over it, separated by a YAML document marker:
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
//	signatures:
//	- signer: upspin@example.com
//	  signature: a1b2c3...-d4e5f6...
//
// Each signature is made by a trust anchor: a key that the reader has pinned
// as entitled to speak for a domain, held in the trust-anchors subdirectory of
// the key directory. It covers the record bytes exactly as they appear in the
// file, so there is no question of canonical encoding, together with the name
// of the signer, so that a signature cannot be relabelled as coming from
// someone else. Both are prefixed with a label, so that a signature made over
// a user record cannot be confused with one made over something else.
//
// An attested record needs no separate verification by the reader: whoever
// holds an anchor key for a domain vouches for every user in it. Pinning one
// key per domain is therefore enough to accept records for all its users.
//
// A record may carry several signatures, which are independent: each covers
// the same record bytes, so one can be appended by anyone at any time without
// the agreement of whoever signed before, and their order means nothing. Two
// arrangements need this. A domain rotating its anchor key publishes records
// signed by both the old key and the new one, so that readers can re-pin at
// their leisure rather than all at the same instant; and one published record
// can carry the signatures of a domain's own anchor and of some third party,
// serving readers who trust either.

// AnchorsDir is the subdirectory of the key directory that holds trust
// anchors: a directory per domain, named for the domain, holding one file per
// anchor, named for the anchor's user name and holding their upspin.User
// record.
const AnchorsDir = "trust-anchors"

// separator marks the end of the record and the start of the signatures. It is
// also a YAML document marker, so an attested record is a valid YAML stream.
const separator = "---"

// signatureLabel prefixes the signed bytes, so that a signature over a user
// record cannot be mistaken for a signature over anything else. It names a
// version, so that a signature made over the earlier construction, which did
// not cover the signer's name, can never be replayed as one over this.
const signatureLabel = "upspin-user-record-v2:"

// An Attestation is one signature on a user record, by a named signer.
type Attestation struct {
	Signer    upspin.UserName
	Signature upspin.Signature
}

// trailer is the YAML form of the signatures that follow a record.
type trailer struct {
	Signatures []signatureEntry `yaml:"signatures"`
}

// signatureEntry is one signature as it appears in the trailer.
type signatureEntry struct {
	Signer    string `yaml:"signer"`
	Signature string `yaml:"signature"`
}

// hashRecord returns the hash that a signature by signer over record covers.
// The signer's name comes first and is followed by a newline, which a user
// name cannot contain, so the two fields cannot be confused for one another.
func hashRecord(record []byte, signer upspin.UserName) []byte {
	h := sha256.New()
	h.Write([]byte(signatureLabel))
	h.Write([]byte(signer))
	h.Write([]byte{'\n'})
	h.Write(record)
	return h.Sum(nil)
}

// Split separates an attested record into the record bytes that are signed and
// the signatures over them, in the order they appear. If data carries no
// attestation it returns the whole of data and no signatures, which is not an
// error: an unattested record is merely one that must be trusted some other
// way.
func Split(data []byte) ([]byte, []Attestation, error) {
	const op errors.Op = "key/trust.Split"

	// The marker is a line of its own; find it without disturbing the
	// bytes before it, which are what the signatures cover.
	record, text, ok := cutLine(data, separator)
	if !ok {
		return data, nil, nil
	}
	var t trailer
	if err := yaml.Unmarshal(text, &t); err != nil {
		return nil, nil, errors.E(op, errors.Invalid, errors.Errorf("parsing signatures: %v", err))
	}
	if len(t.Signatures) == 0 {
		return nil, nil, errors.E(op, errors.Invalid, "no signatures after the document marker")
	}
	var sigs []Attestation
	for _, e := range t.Signatures {
		signer, err := user.Clean(upspin.UserName(e.Signer))
		if err != nil {
			return nil, nil, errors.E(op, errors.Invalid,
				errors.Errorf("signature names an invalid signer %q: %v", e.Signer, err))
		}
		sig, err := parseSignature(e.Signature)
		if err != nil {
			return nil, nil, errors.E(op, errors.Invalid, signer, err)
		}
		sigs = append(sigs, Attestation{Signer: signer, Signature: *sig})
	}
	return record, sigs, nil
}

// parseSignature returns the signature encoded as a pair of hexadecimal
// integers separated by a hyphen.
func parseSignature(text string) (*upspin.Signature, error) {
	fields := strings.Split(text, "-")
	if len(fields) != 2 {
		return nil, errors.Str("malformed signature")
	}
	var r, s big.Int
	if _, ok := r.SetString(fields[0], 16); !ok {
		return nil, errors.Str("malformed signature: bad R")
	}
	if _, ok := s.SetString(fields[1], 16); !ok {
		return nil, errors.Str("malformed signature: bad S")
	}
	return &upspin.Signature{R: &r, S: &s}, nil
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

// Sign returns an attested record for u, signed as signer with f, which must be
// signer's factotum. Readers accept it if they have pinned signer as a trust
// anchor for u's domain.
func Sign(f upspin.Factotum, signer upspin.UserName, u *upspin.User) ([]byte, error) {
	const op errors.Op = "key/trust.Sign"
	if f == nil {
		return nil, errors.E(op, errors.Invalid, "no factotum")
	}
	clean, err := user.Clean(signer)
	if err != nil {
		return nil, errors.E(op, signer, err)
	}
	if err := Validate(u); err != nil {
		return nil, errors.E(op, err)
	}
	record, err := yaml.Marshal(*u)
	if err != nil {
		return nil, errors.E(op, u.Name, err)
	}
	return sign(op, record, nil, f, clean)
}

// Add appends a signature by signer to an attested record, keeping the record
// and the signatures already on it exactly as they stand. A signature covers
// only the record, so one may be added by anyone holding a key, without the
// agreement of whoever signed before. A record carrying no signature yet is
// not an error: appending to nothing is signing, and the result is what Sign
// would have produced.
func Add(data []byte, f upspin.Factotum, signer upspin.UserName) ([]byte, error) {
	const op errors.Op = "key/trust.Add"
	if f == nil {
		return nil, errors.E(op, errors.Invalid, "no factotum")
	}
	clean, err := user.Clean(signer)
	if err != nil {
		return nil, errors.E(op, signer, err)
	}
	record, sigs, err := Split(data)
	if err != nil {
		return nil, errors.E(op, err)
	}
	// Check the record before signing it. The bytes are passed through
	// untouched, so without this Add would be a way to put a signature on
	// anything at all, which Sign is careful not to be.
	if _, err := parseRecord(op, record); err != nil {
		return nil, err
	}
	for _, s := range sigs {
		if s.Signer == clean {
			return nil, errors.E(op, errors.Exist,
				errors.Errorf("%s has already signed this record", clean))
		}
	}
	return sign(op, record, sigs, f, clean)
}

// sign returns record carrying the signatures in sigs and a new one by signer,
// whose name must already be clean.
func sign(op errors.Op, record []byte, sigs []Attestation, f upspin.Factotum, signer upspin.UserName) ([]byte, error) {
	sig, err := f.Sign(hashRecord(record, signer))
	if err != nil {
		return nil, errors.E(op, signer, err)
	}
	var t trailer
	for _, s := range append(sigs, Attestation{Signer: signer, Signature: sig}) {
		t.Signatures = append(t.Signatures, signatureEntry{
			Signer:    string(s.Signer),
			Signature: fmt.Sprintf("%x-%x", s.Signature.R, s.Signature.S),
		})
	}
	text, err := yaml.Marshal(t)
	if err != nil {
		return nil, errors.E(op, signer, err)
	}
	var b bytes.Buffer
	b.Write(record)
	b.WriteString(separator + "\n")
	b.Write(text)
	return b.Bytes(), nil
}

// Verify checks the signature by signer in data against key and returns the
// record it attests to, with the attestation carried on it. It fails if data
// carries no signature by signer.
func Verify(data []byte, signer upspin.UserName, key upspin.PublicKey) (*upspin.User, error) {
	const op errors.Op = "key/trust.Verify"
	record, sigs, err := Split(data)
	if err != nil {
		return nil, errors.E(op, err)
	}
	clean, err := user.Clean(signer)
	if err != nil {
		return nil, errors.E(op, signer, err)
	}
	for _, s := range sigs {
		if s.Signer != clean {
			continue
		}
		if err := factotum.Verify(hashRecord(record, clean), s.Signature, key); err != nil {
			return nil, errors.E(op, errors.Invalid,
				errors.Errorf("the attestation by %s does not verify: %v", clean, err))
		}
		u, err := parseRecord(op, record)
		if err != nil {
			return nil, err
		}
		// Carry the attestation on the record it vouches for. It is not
		// part of what the signatures cover, and so is not in the parsed
		// record, but a record that arrived with evidence should keep
		// it: whoever receives it next can check it too, or pass it on.
		u.Attestation = data
		return u, nil
	}
	return nil, errors.E(op, errors.NotExist,
		errors.Errorf("record carries no attestation by %s", clean))
}

// parseRecord returns the validated record held in the signed bytes.
func parseRecord(op errors.Op, record []byte) (*upspin.User, error) {
	u := new(upspin.User)
	if err := yaml.Unmarshal(record, u); err != nil {
		return nil, errors.E(op, errors.Invalid, errors.Errorf("parsing attested record: %v", err))
	}
	if err := Validate(u); err != nil {
		return nil, errors.E(op, err)
	}
	return u, nil
}

// Accept verifies an attested record against the trust anchors pinned in dir
// and returns the record. It is the check to apply to a record that arrives
// from somewhere the reader does not control. It fails if the record carries no
// attestation, if no anchor is pinned for the record's domain, or if no
// signature on it was made by one of those anchors.
//
// Signatures are considered in turn and the record is accepted on the first
// that verifies under a pinned anchor. A signature by someone who is not a
// pinned anchor for the domain is skipped: it is not addressed to this reader,
// and anyone may append one. A signature that names a pinned anchor and does
// not verify is skipped too, but remembered, so that appending one cannot deny
// the record to a reader for whom some other signature is good.
//
// A record with no signature from a pinned anchor fails with errors.NotExist,
// which means only that the record cannot be believed on its own account; the
// caller may still have some other reason to accept it. A failure of any other
// kind means the record was offered with a signature that does not hold, and
// should be treated as hostile.
func Accept(dir string, data []byte) (*upspin.User, error) {
	const op errors.Op = "key/trust.Accept"
	record, sigs, err := Split(data)
	if err != nil {
		return nil, errors.E(op, err)
	}
	if len(sigs) == 0 {
		return nil, errors.E(op, errors.NotExist, "record carries no attestation")
	}
	// Read the name first, to learn which anchors could have signed it. The
	// record is not trusted until a signature has been checked; nothing is
	// taken from it here but the domain.
	named := new(upspin.User)
	if err := yaml.Unmarshal(record, named); err != nil {
		return nil, errors.E(op, errors.Invalid, errors.Errorf("parsing attested record: %v", err))
	}
	domain, err := domainOf(named.Name)
	if err != nil {
		return nil, errors.E(op, err)
	}
	anchors, err := ReadAnchors(dir, domain)
	if err != nil {
		// Keep the NotExist kind, so that a caller can tell "no anchor
		// is pinned for this domain", which is ordinary, from "the
		// signature does not verify", which is not.
		return nil, errors.E(op, errors.NotExist,
			errors.Errorf("no trust anchor for %s: %v", domain, err))
	}
	var bad error
	for _, s := range sigs {
		anchor := anchorFor(anchors, s.Signer)
		if anchor == nil {
			continue
		}
		if err := factotum.Verify(hashRecord(record, s.Signer), s.Signature, anchor.PublicKey); err != nil {
			if bad == nil {
				bad = errors.Errorf("the attestation by %s does not verify: %v", s.Signer, err)
			}
			continue
		}
		attested, err := parseRecord(op, record)
		if err != nil {
			return nil, err
		}
		// The signature covers the name, so this cannot differ from the
		// domain checked above, but say so rather than rely on that.
		if got, _ := domainOf(attested.Name); got != domain {
			return nil, errors.E(op, errors.Invalid, "attested name does not match")
		}
		attested.Attestation = data
		return attested, nil
	}
	if bad != nil {
		return nil, errors.E(op, errors.Invalid, named.Name, bad)
	}
	return nil, errors.E(op, errors.NotExist, named.Name,
		errors.Errorf("no signature by a trust anchor pinned for %s", domain))
}

// anchorFor returns the anchor named signer, or nil if there is none.
func anchorFor(anchors []*upspin.User, signer upspin.UserName) *upspin.User {
	for _, a := range anchors {
		if a.Name == signer {
			return a
		}
	}
	return nil
}

// domainOf returns the domain component of a user name.
func domainOf(name upspin.UserName) (string, error) {
	_, _, domain, err := user.Parse(name)
	if err != nil {
		return "", err
	}
	return domain, nil
}

// anchorDir returns the name of the directory holding the trust anchors for
// domain, within dir.
func anchorDir(op errors.Op, dir, domain string) (string, error) {
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

// anchorFileName returns the name of the file holding the anchor named name for
// domain, within dir, and the cleaned form of the name.
func anchorFileName(op errors.Op, dir, domain string, name upspin.UserName) (string, upspin.UserName, error) {
	d, err := anchorDir(op, dir, domain)
	if err != nil {
		return "", "", err
	}
	clean, err := user.Clean(name)
	if err != nil {
		return "", "", errors.E(op, name, err)
	}
	// A valid user name can never contain a path separator, but this value
	// is about to become a file name, so do not take that on trust.
	if filepath.Base(string(clean)) != string(clean) {
		return "", "", errors.E(op, name, errors.Invalid, "user name is not a valid file name")
	}
	return filepath.Join(d, string(clean)), clean, nil
}

// ReadAnchors returns the trust anchors pinned for domain in dir, sorted by
// name. If none is pinned it returns an error of kind errors.NotExist.
//
// The anchors for a domain live in a directory named for it, one file per
// anchor, named for the anchor's user name. A plain file at that path is read
// as a single anchor: that was the layout before a domain could have more than
// one, and WriteAnchor migrates it when a second anchor is added.
//
// An anchor that is present but unusable is an error, never a silent absence.
// Skipping it would let a damaged or tampered anchor file quietly reduce what
// the reader will accept.
func ReadAnchors(dir, domain string) ([]*upspin.User, error) {
	const op errors.Op = "key/trust.ReadAnchors"
	d, err := anchorDir(op, dir, domain)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(d)
	if os.IsNotExist(err) {
		return nil, errors.E(op, errors.NotExist, errors.Errorf("no trust anchor for %s", domain))
	}
	if err != nil {
		return nil, errors.E(op, errors.IO, err)
	}
	if !info.IsDir() {
		u, err := readAnchorFile(op, d)
		if err != nil {
			return nil, err
		}
		return []*upspin.User{u}, nil
	}
	entries, err := os.ReadDir(d)
	if err != nil {
		return nil, errors.E(op, errors.IO, err)
	}
	var anchors []*upspin.User
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		file := filepath.Join(d, e.Name())
		u, err := readAnchorFile(op, file)
		if err != nil {
			return nil, err
		}
		if string(u.Name) != e.Name() {
			return nil, errors.E(op, errors.Invalid,
				errors.Errorf("%s holds a record for %q", file, u.Name))
		}
		anchors = append(anchors, u)
	}
	if len(anchors) == 0 {
		return nil, errors.E(op, errors.NotExist, errors.Errorf("no trust anchor for %s", domain))
	}
	sort.Slice(anchors, func(i, j int) bool { return anchors[i].Name < anchors[j].Name })
	return anchors, nil
}

// ReadAnchor returns the anchor named name pinned for domain in dir. If there
// is no such anchor it returns an error of kind errors.NotExist.
func ReadAnchor(dir, domain string, name upspin.UserName) (*upspin.User, error) {
	const op errors.Op = "key/trust.ReadAnchor"
	clean, err := user.Clean(name)
	if err != nil {
		return nil, errors.E(op, name, err)
	}
	anchors, err := ReadAnchors(dir, domain)
	if err != nil {
		return nil, errors.E(op, err)
	}
	if u := anchorFor(anchors, clean); u != nil {
		return u, nil
	}
	return nil, errors.E(op, errors.NotExist,
		errors.Errorf("%s is not a trust anchor for %s", clean, domain))
}

// readAnchorFile returns the validated anchor record held in a file.
func readAnchorFile(op errors.Op, file string) (*upspin.User, error) {
	data, err := os.ReadFile(file)
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

// WriteAnchor pins u as a trust anchor for domain in dir, replacing any anchor
// already pinned there under the same name and leaving any other alongside it.
func WriteAnchor(dir, domain string, u *upspin.User) error {
	const op errors.Op = "key/trust.WriteAnchor"
	if err := Validate(u); err != nil {
		return errors.E(op, err)
	}
	d, err := anchorDir(op, dir, domain)
	if err != nil {
		return err
	}
	file, _, err := anchorFileName(op, dir, domain, u.Name)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(*u)
	if err != nil {
		return errors.E(op, u.Name, err)
	}
	if err := migrateAnchor(op, d); err != nil {
		return err
	}
	if err := os.MkdirAll(d, 0700); err != nil {
		return errors.E(op, errors.IO, err)
	}
	if err := os.WriteFile(file, data, 0600); err != nil {
		return errors.E(op, errors.IO, err)
	}
	return nil
}

// migrateAnchor converts the single-file form of a domain's anchor into the
// directory form, so that another anchor can be pinned beside it. It does
// nothing if the path is already a directory or does not exist.
func migrateAnchor(op errors.Op, d string) error {
	info, err := os.Stat(d)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.E(op, errors.IO, err)
	}
	if info.IsDir() {
		return nil
	}
	u, err := readAnchorFile(op, d)
	if err != nil {
		return err
	}
	if filepath.Base(string(u.Name)) != string(u.Name) {
		return errors.E(op, u.Name, errors.Invalid, "user name is not a valid file name")
	}
	data, err := os.ReadFile(d)
	if err != nil {
		return errors.E(op, errors.IO, err)
	}
	// Move the file aside before making the directory in its place, so that
	// an interruption leaves the old anchor readable rather than nothing.
	aside := d + ".moving"
	if err := os.Rename(d, aside); err != nil {
		return errors.E(op, errors.IO, err)
	}
	if err := os.MkdirAll(d, 0700); err != nil {
		return errors.E(op, errors.IO, err)
	}
	if err := os.WriteFile(filepath.Join(d, string(u.Name)), data, 0600); err != nil {
		return errors.E(op, errors.IO, err)
	}
	if err := os.Remove(aside); err != nil {
		return errors.E(op, errors.IO, err)
	}
	return nil
}

// RemoveAnchor deletes the anchor named name pinned for domain in dir.
func RemoveAnchor(dir, domain string, name upspin.UserName) error {
	const op errors.Op = "key/trust.RemoveAnchor"
	d, err := anchorDir(op, dir, domain)
	if err != nil {
		return err
	}
	file, clean, err := anchorFileName(op, dir, domain, name)
	if err != nil {
		return err
	}
	info, err := os.Stat(d)
	if os.IsNotExist(err) {
		return errors.E(op, errors.NotExist, errors.Errorf("no trust anchor for %s", domain))
	}
	if err != nil {
		return errors.E(op, errors.IO, err)
	}
	if !info.IsDir() {
		// The single-file form holds one anchor; it must be this one.
		u, err := readAnchorFile(op, d)
		if err != nil {
			return err
		}
		if u.Name != clean {
			return errors.E(op, errors.NotExist,
				errors.Errorf("%s is not a trust anchor for %s", clean, domain))
		}
		file = d
	}
	if err := os.Remove(file); err != nil {
		if os.IsNotExist(err) {
			return errors.E(op, errors.NotExist,
				errors.Errorf("%s is not a trust anchor for %s", clean, domain))
		}
		return errors.E(op, errors.IO, err)
	}
	// Take the directory away with its last anchor. This fails while it
	// still holds one, which is the intent.
	if info.IsDir() {
		os.Remove(d)
	}
	return nil
}

// RemoveAnchors deletes every trust anchor pinned for domain in dir.
func RemoveAnchors(dir, domain string) error {
	const op errors.Op = "key/trust.RemoveAnchors"
	d, err := anchorDir(op, dir, domain)
	if err != nil {
		return err
	}
	if _, err := os.Stat(d); os.IsNotExist(err) {
		return errors.E(op, errors.NotExist, errors.Errorf("no trust anchor for %s", domain))
	}
	if err := os.RemoveAll(d); err != nil {
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
		if _, _, _, err := user.Parse(upspin.UserName("anyone@" + e.Name())); err != nil {
			// Not a domain; not ours.
			continue
		}
		domains = append(domains, e.Name())
	}
	sort.Strings(domains)
	return domains, nil
}
