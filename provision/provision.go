// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package provision describes an Upspin identity completely enough to set it
// up on another device: the configuration values, the key pair, and the trust
// the device needs to resolve other users. A Document is what "upspin qr"
// shows as a QR code and what the Android app installs from.
//
// The document carries the private key. It must travel only over channels
// the owner trusts, such as a screen in front of them.
package provision // import "upspin.io/provision"

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v2"

	"upspin.io/config"
	"upspin.io/errors"
	"upspin.io/factotum"
	"upspin.io/key/trust"
	"upspin.io/pack"
	"upspin.io/path"
	"upspin.io/upspin"
	"upspin.io/user"
)

// Document is the provisioning document. Its YAML form uses the keys of a
// configuration file where the two coincide, so that someone reading one
// recognizes the other.
type Document struct {
	UserName     string   `yaml:"username"`
	DirServer    string   `yaml:"dirserver"`
	StoreServer  string   `yaml:"storeserver"`
	KeyServer    string   `yaml:"keyserver,omitempty"`
	Packing      string   `yaml:"packing,omitempty"`
	KeySets      []string `yaml:"keysets,omitempty"`
	KeyDiscovery bool     `yaml:"keydiscovery,omitempty"`

	// PublicKey and SecretKey are the contents of public.upspinkey and
	// secret.upspinkey, less the seed that keygen leaves as a comment
	// on the secret, which the device does not need; ArchivedKeys is
	// secret2.upspinkey, the keys retired by rotation that are still
	// needed to read old files.
	PublicKey    string `yaml:"publickey"`
	SecretKey    string `yaml:"secretkey"`
	ArchivedKeys string `yaml:"archivedkeys,omitempty"`

	// Anchors are the pinned trust anchors, each a plain upspin.User
	// record in YAML with the domains it is pinned for; Pins are pinned
	// leaf records as stored, so an attestation a pin carries travels
	// with it.
	Anchors []Anchor `yaml:"anchors,omitempty"`
	Pins    []string `yaml:"pins,omitempty"`

	// TLSCerts holds PEM certificates that replace the system roots
	// when verifying servers, for servers that use a private CA.
	TLSCerts []string `yaml:"tlscerts,omitempty"`
}

// Anchor is a trust anchor with the domains it is pinned for. One key is
// often the anchor for several domains, and a record is long, so it is
// carried once.
type Anchor struct {
	Domains []string `yaml:"domains"`
	Record  string   `yaml:"record"`
}

// The layout Install writes under its directory. ConfigFile is written last,
// so its presence means the installation is complete.
const (
	ConfigFile  = "config"
	secretsDir  = "secrets"
	keysDir     = "keys"
	tlsCertsDir = "tlscerts"
)

// Gather builds the document for the identity cfg describes, reading the key
// files from the secrets directory and the anchors from the keydir. With pins
// set, the pinned leaf records are included too; they are usually many and
// are only needed on a device that has no other way to learn them.
func Gather(cfg upspin.Config, pins bool) (*Document, error) {
	const op errors.Op = "provision.Gather"
	if cfg.Factotum() == nil {
		return nil, errors.E(op, errors.Invalid, errors.Str("configuration has no keys"))
	}
	d := &Document{
		UserName:     string(cfg.UserName()),
		DirServer:    cfg.DirEndpoint().String(),
		StoreServer:  cfg.StoreEndpoint().String(),
		KeyDiscovery: trust.Discovery(cfg),
	}
	if cfg.KeyEndpoint().Transport != upspin.Unassigned {
		d.KeyServer = cfg.KeyEndpoint().String()
	}
	if p := pack.Lookup(cfg.Packing()); p != nil {
		d.Packing = p.String()
	}
	sets, err := trust.Sets(cfg)
	if err != nil {
		return nil, errors.E(op, err)
	}
	for _, set := range sets {
		d.KeySets = append(d.KeySets, string(set))
	}

	secrets := strings.TrimSpace(cfg.Value("secrets"))
	if secrets == "" {
		secrets, err = config.DefaultSecretsDir(cfg.UserName())
		if err != nil {
			return nil, errors.E(op, err)
		}
	}
	pub, err := os.ReadFile(filepath.Join(secrets, "public.upspinkey"))
	if err != nil {
		return nil, errors.E(op, errors.IO, err)
	}
	sec, err := os.ReadFile(filepath.Join(secrets, "secret.upspinkey"))
	if err != nil {
		return nil, errors.E(op, errors.IO, err)
	}
	old, err := os.ReadFile(filepath.Join(secrets, "secret2.upspinkey"))
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.E(op, errors.IO, err)
	}
	if upspin.PublicKey(pub) != cfg.Factotum().PublicKey() {
		return nil, errors.E(op, errors.Invalid, errors.Errorf("%s: public key does not match the configuration's", secrets))
	}
	d.PublicKey = string(pub)
	d.SecretKey = strings.TrimSpace(strings.SplitN(string(sec), "#", 2)[0]) + "\n"
	d.ArchivedKeys = string(old)

	keydir, err := trust.Dir(cfg)
	if err != nil {
		return nil, errors.E(op, err)
	}
	if keydir != "" {
		domains, err := trust.ListAnchors(keydir)
		if err != nil {
			return nil, errors.E(op, err)
		}
		for _, domain := range domains {
			anchors, err := trust.ReadAnchors(keydir, domain)
			if err != nil {
				return nil, errors.E(op, err)
			}
			for _, u := range anchors {
				rec, err := yaml.Marshal(*u)
				if err != nil {
					return nil, errors.E(op, err)
				}
				d.addAnchor(domain, string(rec))
			}
		}
		if pins {
			names, err := trust.List(keydir)
			if err != nil {
				return nil, errors.E(op, err)
			}
			for _, name := range names {
				rec, err := trust.ReadRaw(keydir, name)
				if err != nil {
					return nil, errors.E(op, err)
				}
				d.Pins = append(d.Pins, string(rec))
			}
		}
	}

	if certs := strings.TrimSpace(cfg.Value("tlscerts")); certs != "" {
		files, err := filepath.Glob(filepath.Join(certs, "*.pem"))
		if err != nil {
			return nil, errors.E(op, errors.IO, err)
		}
		sort.Strings(files)
		for _, file := range files {
			pem, err := os.ReadFile(file)
			if err != nil {
				return nil, errors.E(op, errors.IO, err)
			}
			d.TLSCerts = append(d.TLSCerts, string(pem))
		}
	}
	return d, nil
}

// addAnchor records that the anchor with this record is pinned for domain,
// alongside the record's other domains if it is already present.
func (d *Document) addAnchor(domain, record string) {
	for i := range d.Anchors {
		if d.Anchors[i].Record == record {
			d.Anchors[i].Domains = append(d.Anchors[i].Domains, domain)
			return
		}
	}
	d.Anchors = append(d.Anchors, Anchor{Domains: []string{domain}, Record: record})
}

// Parse decodes a document, in plain or compact form, and checks that it is complete and consistent:
// the name and endpoints parse, the packing is known, the keys are a pair,
// and every record it carries is a valid user record.
func Parse(data []byte) (*Document, error) {
	const op errors.Op = "provision.Parse"
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte(CompactPrefix)) {
		var err error
		data, err = decodeCompact(strings.TrimPrefix(string(bytes.TrimSpace(data)), CompactPrefix))
		if err != nil {
			return nil, errors.E(op, err)
		}
	}
	d := new(Document)
	if err := yaml.UnmarshalStrict(data, d); err != nil {
		return nil, errors.E(op, errors.Invalid, err)
	}
	if err := d.validate(); err != nil {
		return nil, errors.E(op, err)
	}
	return d, nil
}

// Marshal encodes the document as YAML.
func (d *Document) Marshal() ([]byte, error) {
	const op errors.Op = "provision.Marshal"
	if err := d.validate(); err != nil {
		return nil, errors.E(op, err)
	}
	data, err := yaml.Marshal(d)
	if err != nil {
		return nil, errors.E(op, err)
	}
	return data, nil
}

func (d *Document) validate() error {
	name, err := user.Clean(upspin.UserName(d.UserName))
	if err != nil {
		return err
	}
	d.UserName = string(name)
	for _, ep := range []struct {
		key, value string
		required   bool
	}{
		{"dirserver", d.DirServer, true},
		{"storeserver", d.StoreServer, true},
		{"keyserver", d.KeyServer, false},
	} {
		if ep.value == "" {
			if ep.required {
				return errors.E(errors.Invalid, errors.Errorf("%s is missing", ep.key))
			}
			continue
		}
		if _, err := upspin.ParseEndpoint(ep.value); err != nil {
			return errors.E(errors.Invalid, errors.Errorf("%s: %v", ep.key, err))
		}
	}
	if d.Packing != "" && pack.LookupByName(d.Packing) == nil {
		return errors.E(errors.Invalid, errors.Errorf("unknown packing %q", d.Packing))
	}
	for _, set := range d.KeySets {
		if _, err := path.Parse(upspin.PathName(set)); err != nil {
			return errors.E(errors.Invalid, errors.Errorf("keysets: %s: %v", set, err))
		}
	}
	if d.PublicKey == "" || d.SecretKey == "" {
		return errors.E(errors.Invalid, errors.Str("the key pair is missing"))
	}
	if _, err := factotum.NewFromKeys([]byte(d.PublicKey), []byte(d.SecretKey), []byte(d.ArchivedKeys)); err != nil {
		return errors.E(errors.Invalid, errors.Errorf("keys: %v", err))
	}
	for _, a := range d.Anchors {
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
	for _, p := range d.Pins {
		if _, err := parseRecord(p); err != nil {
			return errors.E(errors.Invalid, errors.Errorf("pin: %v", err))
		}
	}
	return nil
}

// parseRecord reads a user record that may carry an attestation.
func parseRecord(rec string) (*upspin.User, error) {
	record, _, err := trust.Split([]byte(rec))
	if err != nil {
		return nil, err
	}
	u := new(upspin.User)
	if err := yaml.Unmarshal(record, u); err != nil {
		return nil, err
	}
	if err := trust.Validate(u); err != nil {
		return nil, err
	}
	return u, nil
}

// Installed reports whether dir holds a complete installation.
func Installed(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ConfigFile))
	return err == nil
}

// Install writes the identity under dir, which must not hold one already: the
// key files, the pinned trust, any certificates, and last a configuration
// file that names them all by absolute path, so that config.FromFile on that
// file yields a working client configuration.
func (d *Document) Install(dir string) error {
	const op errors.Op = "provision.Install"
	if err := d.validate(); err != nil {
		return errors.E(op, err)
	}
	if !filepath.IsAbs(dir) {
		return errors.E(op, errors.Invalid, errors.Errorf("%s is not an absolute path", dir))
	}
	if Installed(dir) {
		return errors.E(op, errors.Exist, errors.Errorf("%s already holds an identity", dir))
	}
	secrets := filepath.Join(dir, secretsDir)
	keys := filepath.Join(dir, keysDir)
	certs := filepath.Join(dir, tlsCertsDir)
	if err := os.MkdirAll(secrets, 0700); err != nil {
		return errors.E(op, errors.IO, err)
	}
	for _, f := range []struct{ name, data string }{
		{"public.upspinkey", d.PublicKey},
		{"secret.upspinkey", d.SecretKey},
		{"secret2.upspinkey", d.ArchivedKeys},
	} {
		if f.data == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(secrets, f.name), []byte(f.data), 0600); err != nil {
			return errors.E(op, errors.IO, err)
		}
	}
	if err := os.MkdirAll(keys, 0700); err != nil {
		return errors.E(op, errors.IO, err)
	}
	for _, a := range d.Anchors {
		u, err := parseRecord(a.Record)
		if err != nil {
			return errors.E(op, err)
		}
		for _, domain := range a.Domains {
			if err := trust.WriteAnchor(keys, domain, u); err != nil {
				return errors.E(op, err)
			}
		}
	}
	for _, p := range d.Pins {
		if err := trust.Pin(keys, []byte(p)); err != nil {
			return errors.E(op, err)
		}
	}
	if len(d.TLSCerts) > 0 {
		if err := os.MkdirAll(certs, 0700); err != nil {
			return errors.E(op, errors.IO, err)
		}
		for i, pem := range d.TLSCerts {
			name := filepath.Join(certs, fmt.Sprintf("cert%02d.pem", i))
			if err := os.WriteFile(name, []byte(pem), 0600); err != nil {
				return errors.E(op, errors.IO, err)
			}
		}
	}

	var cfg bytes.Buffer
	line := func(key, value string) {
		cfg.WriteString(key + ": " + value + "\n")
	}
	line("username", d.UserName)
	line("dirserver", d.DirServer)
	line("storeserver", d.StoreServer)
	if d.KeyServer != "" {
		line("keyserver", d.KeyServer)
	} else {
		line("keyserver", "unassigned")
	}
	if d.Packing != "" {
		line("packing", d.Packing)
	}
	line("secrets", secrets)
	line(trust.ConfigKey, keys)
	if len(d.KeySets) > 0 {
		cfg.WriteString("keysets:\n")
		for _, set := range d.KeySets {
			cfg.WriteString("- " + set + "\n")
		}
	}
	if d.KeyDiscovery {
		line("keydiscovery", "true")
	}
	if len(d.TLSCerts) > 0 {
		line("tlscerts", certs)
	}
	if err := os.WriteFile(filepath.Join(dir, ConfigFile), cfg.Bytes(), 0600); err != nil {
		return errors.E(op, errors.IO, err)
	}
	return nil
}
