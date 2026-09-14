// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package provision

import (
	"bytes"
	"strings"

	"gopkg.in/yaml.v2"

	"upspin.io/errors"
	"upspin.io/factotum"
	"upspin.io/key/trust"
	"upspin.io/upspin"
	"upspin.io/user"
)

// Trust is a document carrying trust anchors alone, for handing the anchors
// of a domain to a device that already has an identity. It holds no secret,
// but whoever installs it will believe every record those anchors attest,
// so it should still come from the anchor's owner directly: a code on their
// screen, not a forwarded message.
type Trust struct {
	Anchors []Anchor `yaml:"anchors"`
}

// TrustPrefix marks a trust document in compact form.
const TrustPrefix = "UPSPINTRUST1:"

// GatherTrust collects the anchors pinned in cfg's keydir, for the domains
// named or for all of them when none are.
func GatherTrust(cfg upspin.Config, domains ...string) (*Trust, error) {
	const op errors.Op = "provision.GatherTrust"
	keydir, err := trust.Dir(cfg)
	if err != nil {
		return nil, errors.E(op, err)
	}
	if keydir == "" {
		return nil, errors.E(op, errors.Invalid, errors.Str("configuration names no keydir"))
	}
	if len(domains) == 0 {
		domains, err = trust.ListAnchors(keydir)
		if err != nil {
			return nil, errors.E(op, err)
		}
	}
	t := new(Trust)
	for _, domain := range domains {
		anchors, err := trust.ReadAnchors(keydir, domain)
		if err != nil {
			return nil, errors.E(op, err)
		}
		if len(anchors) == 0 {
			return nil, errors.E(op, errors.NotExist, errors.Errorf("no trust anchor is pinned for %s", domain))
		}
		for _, u := range anchors {
			rec, err := yaml.Marshal(*u)
			if err != nil {
				return nil, errors.E(op, err)
			}
			t.add(domain, string(rec))
		}
	}
	return t, nil
}

// SelfTrust describes cfg's own user as the anchor for the domains named,
// or for the user's own domain when none are. It is how the owner of a
// domain's anchor key offers it.
func SelfTrust(cfg upspin.Config, domains ...string) (*Trust, error) {
	const op errors.Op = "provision.SelfTrust"
	if cfg.Factotum() == nil {
		return nil, errors.E(op, errors.Invalid, errors.Str("configuration has no keys"))
	}
	name, err := user.Clean(cfg.UserName())
	if err != nil {
		return nil, errors.E(op, err)
	}
	if len(domains) == 0 {
		_, _, domain, err := user.Parse(name)
		if err != nil {
			return nil, errors.E(op, err)
		}
		domains = []string{domain}
	}
	u := upspin.User{
		Name:      name,
		Dirs:      []upspin.Endpoint{cfg.DirEndpoint()},
		Stores:    []upspin.Endpoint{cfg.StoreEndpoint()},
		PublicKey: cfg.Factotum().PublicKey(),
	}
	rec, err := yaml.Marshal(u)
	if err != nil {
		return nil, errors.E(op, err)
	}
	t := new(Trust)
	for _, domain := range domains {
		t.add(domain, string(rec))
	}
	return t, nil
}

func (t *Trust) add(domain, record string) {
	for i := range t.Anchors {
		if t.Anchors[i].Record == record {
			t.Anchors[i].Domains = append(t.Anchors[i].Domains, domain)
			return
		}
	}
	t.Anchors = append(t.Anchors, Anchor{Domains: []string{domain}, Record: record})
}

// ParseTrust decodes a trust document, in plain or compact form.
func ParseTrust(data []byte) (*Trust, error) {
	const op errors.Op = "provision.ParseTrust"
	// Only the compact form is trimmed: in YAML the last newline belongs
	// to the record's final block scalar.
	head := bytes.TrimSpace(data)
	if bytes.HasPrefix(head, []byte(CompactPrefix)) {
		return nil, errors.E(op, errors.Invalid, errors.Str("this is an identity, not a trust anchor"))
	}
	if bytes.HasPrefix(head, []byte(TrustPrefix)) {
		var err error
		data, err = decodeCompact(strings.TrimPrefix(string(head), TrustPrefix))
		if err != nil {
			return nil, errors.E(op, err)
		}
	}
	t := new(Trust)
	if err := yaml.UnmarshalStrict(data, t); err != nil {
		return nil, errors.E(op, errors.Invalid, err)
	}
	if err := t.validate(); err != nil {
		return nil, errors.E(op, err)
	}
	return t, nil
}

func (t *Trust) validate() error {
	if len(t.Anchors) == 0 {
		return errors.E(errors.Invalid, errors.Str("no trust anchors"))
	}
	for _, a := range t.Anchors {
		if len(a.Domains) == 0 {
			return errors.E(errors.Invalid, errors.Str("anchor names no domain"))
		}
		for _, domain := range a.Domains {
			if _, _, _, err := user.Parse(upspin.UserName("anyone@" + domain)); err != nil {
				return errors.E(errors.Invalid, errors.Errorf("anchor domain %q: %v", domain, err))
			}
		}
		if _, err := parseRecord(a.Record); err != nil {
			return errors.E(errors.Invalid, errors.Errorf("anchor for %s: %v", strings.Join(a.Domains, ", "), err))
		}
	}
	return nil
}

// Marshal encodes the document as YAML.
func (t *Trust) Marshal() ([]byte, error) {
	const op errors.Op = "provision.Trust.Marshal"
	if err := t.validate(); err != nil {
		return nil, errors.E(op, err)
	}
	data, err := yaml.Marshal(t)
	if err != nil {
		return nil, errors.E(op, err)
	}
	return data, nil
}

// Encode returns the document in compact form, for a QR code.
func (t *Trust) Encode() (string, error) {
	const op errors.Op = "provision.Trust.Encode"
	data, err := t.Marshal()
	if err != nil {
		return "", errors.E(op, err)
	}
	return TrustPrefix + encodeCompact(data), nil
}

// Describe returns one line per anchor, naming the domains, the user and
// the key's fingerprint: what a person must check before installing it.
func (t *Trust) Describe() string {
	var b strings.Builder
	for _, a := range t.Anchors {
		u, err := parseRecord(a.Record)
		if err != nil {
			continue
		}
		b.WriteString(strings.Join(a.Domains, ", ") + ": " + string(u.Name) + "\n  " + factotum.Fingerprint(u.PublicKey) + "\n")
	}
	return b.String()
}

// Install pins every anchor in keydir, beside any already there.
func (t *Trust) Install(keydir string) error {
	const op errors.Op = "provision.Trust.Install"
	if err := t.validate(); err != nil {
		return errors.E(op, err)
	}
	for _, a := range t.Anchors {
		u, err := parseRecord(a.Record)
		if err != nil {
			return errors.E(op, err)
		}
		for _, domain := range a.Domains {
			if err := trust.WriteAnchor(keydir, domain, u); err != nil {
				return errors.E(op, err)
			}
		}
	}
	return nil
}
