// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package provision

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"

	"upspin.io/config"
	"upspin.io/errors"
	"upspin.io/key/keygen"
	"upspin.io/key/trust"
	"upspin.io/upspin"
)

const (
	alice  = "alice@example.com"
	anchor = "upspin@example.com"
)

// testDocument builds a document for alice with one anchor for example.com,
// one pinned leaf, and one certificate. The keys are freshly generated.
func testDocument(t *testing.T) *Document {
	t.Helper()
	pub, sec, _, err := keygen.Generate("p256")
	if err != nil {
		t.Fatal(err)
	}
	anchorPub, _, _, err := keygen.Generate("p256")
	if err != nil {
		t.Fatal(err)
	}
	leafPub, _, _, err := keygen.Generate("p256")
	if err != nil {
		t.Fatal(err)
	}
	record := func(name, key string) string {
		return "name: " + name + "\ndirs:\n- remote,dir.example.com:443\nstores:\n- remote,store.example.com:443\npublickey: |\n  " +
			strings.ReplaceAll(strings.TrimSpace(key), "\n", "\n  ") + "\n"
	}
	return &Document{
		UserName:     alice,
		DirServer:    "remote,dir.example.com:443",
		StoreServer:  "remote,store.example.com:443",
		Packing:      "ee",
		KeySets:      []string{anchor + "/Keys"},
		KeyDiscovery: true,
		PublicKey:    pub,
		SecretKey:    sec,
		Anchors:      []Anchor{{Domains: []string{"example.com", "example.net"}, Record: record(anchor, anchorPub)}},
		Pins:         []string{record("bob@example.org", leafPub)},
		TLSCerts:     []string{"-----BEGIN CERTIFICATE-----\nnot really\n-----END CERTIFICATE-----\n"},
	}
}

func TestRoundTrip(t *testing.T) {
	d := testDocument(t)
	data, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, data)
	}
	if !reflect.DeepEqual(parsed, d) {
		t.Fatalf("parsed document differs:\n%#v\nwant\n%#v", parsed, d)
	}
}

func TestCompact(t *testing.T) {
	d := testDocument(t)
	compact, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(compact, CompactPrefix) {
		t.Fatalf("compact form %q", compact)
	}
	for _, c := range compact[len(CompactPrefix):] {
		if !strings.ContainsRune(base45Alphabet, c) {
			t.Fatalf("compact form has %q, outside the alphanumeric set", c)
		}
	}
	plain, _ := d.Marshal()
	if len(compact) > len(plain) {
		t.Errorf("compact form is %d bytes, plain %d", len(compact), len(plain))
	}
	parsed, err := Parse([]byte(compact + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, d) {
		t.Fatalf("parsed compact document differs:\n%#v\nwant\n%#v", parsed, d)
	}
	for _, bad := range []string{
		CompactPrefix,
		CompactPrefix + "A",
		CompactPrefix + "abc",
		CompactPrefix + ":::",
		CompactPrefix + "000000",
	} {
		if _, err := Parse([]byte(bad)); !errors.Match(errors.E(errors.Invalid), err) {
			t.Errorf("%q: got %v, want Invalid", bad, err)
		}
	}
}

func TestBase45(t *testing.T) {
	// The examples of RFC 9285, section 4.3.
	for _, test := range []struct{ in, out string }{
		{"AB", "BB8"},
		{"Hello!!", "%69 VD92EX0"},
		{"base-45", "UJCLQE7W581"},
		{"", ""},
		{"\x00", "00"},
		{"\xff\xff", "FGW"},
	} {
		got := base45Encode([]byte(test.in))
		if got != test.out {
			t.Errorf("encode %q: %q, want %q", test.in, got, test.out)
		}
		back, err := base45Decode(test.out)
		if err != nil || string(back) != test.in {
			t.Errorf("decode %q: %q, %v; want %q", test.out, back, err, test.in)
		}
	}
	for _, bad := range []string{"A", "GGW", "ZZZ", "a", "ZZ"} {
		if _, err := base45Decode(bad); err == nil {
			t.Errorf("decode %q succeeded", bad)
		}
	}
}

func TestInstall(t *testing.T) {
	d := testDocument(t)
	dir := filepath.Join(t.TempDir(), "upspin")
	if Installed(dir) {
		t.Fatal("Installed before Install")
	}
	if err := d.Install(dir); err != nil {
		t.Fatal(err)
	}
	if !Installed(dir) {
		t.Fatal("not Installed after Install")
	}
	if err := d.Install(dir); !errors.Match(errors.E(errors.Exist), err) {
		t.Fatalf("second Install: got %v, want Exist", err)
	}

	cfg, err := config.FromFile(filepath.Join(dir, ConfigFile))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.UserName(); got != alice {
		t.Errorf("user name %q, want %q", got, alice)
	}
	if got := cfg.DirEndpoint().String(); got != d.DirServer {
		t.Errorf("dir endpoint %q, want %q", got, d.DirServer)
	}
	if got := cfg.StoreEndpoint().String(); got != d.StoreServer {
		t.Errorf("store endpoint %q, want %q", got, d.StoreServer)
	}
	if got := cfg.KeyEndpoint().Transport; got != upspin.Unassigned {
		t.Errorf("key endpoint transport %v, want unassigned", got)
	}
	if got := cfg.Factotum().PublicKey(); string(got) != d.PublicKey {
		t.Errorf("public key %q, want %q", got, d.PublicKey)
	}
	if got := cfg.Packing(); got != upspin.EEPack {
		t.Errorf("packing %v, want ee", got)
	}
	if !trust.Discovery(cfg) {
		t.Error("discovery is off")
	}
	sets, err := trust.Sets(cfg)
	if err != nil || len(sets) != 1 || string(sets[0]) != d.KeySets[0] {
		t.Errorf("sets %v, %v; want %v", sets, err, d.KeySets)
	}
	keydir, err := trust.Dir(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"example.com", "example.net"} {
		anchors, err := trust.ReadAnchors(keydir, domain)
		if err != nil || len(anchors) != 1 || anchors[0].Name != anchor {
			t.Errorf("anchors for %s: %v, %v; want one for %s", domain, anchors, err, anchor)
		}
	}
	bob, err := trust.Read(keydir, "bob@example.org")
	if err != nil || bob.Name != "bob@example.org" {
		t.Errorf("pinned bob: %v, %v", bob, err)
	}
	certs, _ := filepath.Glob(filepath.Join(cfg.Value("tlscerts"), "*.pem"))
	if len(certs) != 1 {
		t.Errorf("certificates %v, want one", certs)
	}
	info, err := os.Stat(filepath.Join(dir, secretsDir, "secret.upspinkey"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("secret key mode %o, want 0600", mode)
	}

	// What was installed gathers back as what was installed.
	back, err := Gather(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, d) {
		t.Errorf("gathered document differs:\n%#v\nwant\n%#v", back, d)
	}
	back, err = Gather(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if back.Pins != nil {
		t.Errorf("gathered pins without asking: %v", back.Pins)
	}

	// The seed keygen writes as a comment on the secret stays behind.
	secretFile := filepath.Join(dir, secretsDir, "secret.upspinkey")
	if err := os.WriteFile(secretFile, []byte(strings.TrimSpace(d.SecretKey)+" # seed-words-here\n"), 0600); err != nil {
		t.Fatal(err)
	}
	back, err = Gather(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if back.SecretKey != d.SecretKey {
		t.Errorf("gathered secret %q, want %q", back.SecretKey, d.SecretKey)
	}
}

func TestParseRejects(t *testing.T) {
	good := testDocument(t)
	for _, test := range []struct {
		name string
		edit func(d *Document)
	}{
		{"no user", func(d *Document) { d.UserName = "" }},
		{"bad user", func(d *Document) { d.UserName = "alice" }},
		{"no dirserver", func(d *Document) { d.DirServer = "" }},
		{"bad dirserver", func(d *Document) { d.DirServer = "carrier pigeon" }},
		{"bad keyserver", func(d *Document) { d.KeyServer = "remote" }},
		{"bad packing", func(d *Document) { d.Packing = "rot13" }},
		{"bad keyset", func(d *Document) { d.KeySets = []string{"nobody/Keys"} }},
		{"no secret", func(d *Document) { d.SecretKey = "" }},
		{"wrong secret", func(d *Document) { d.SecretKey = "12345" }},
		{"bad anchor domain", func(d *Document) { d.Anchors[0].Domains = []string{"not a domain"} }},
		{"no anchor domain", func(d *Document) { d.Anchors[0].Domains = nil }},
		{"bad anchor record", func(d *Document) { d.Anchors[0].Record = "name: nobody\n" }},
		{"bad pin", func(d *Document) { d.Pins[0] = "publickey: |\n  p256\n  1\n  2\n" }},
	} {
		d := *good
		d.Anchors = append([]Anchor(nil), good.Anchors...)
		d.Pins = append([]string(nil), good.Pins...)
		test.edit(&d)
		data, err := yamlMarshal(&d)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(data); !errors.Match(errors.E(errors.Invalid), err) {
			t.Errorf("%s: got %v, want Invalid", test.name, err)
		}
	}
	if _, err := Parse([]byte("username: x\nunknownkey: 1\n")); !errors.Match(errors.E(errors.Invalid), err) {
		t.Errorf("unknown key: got %v, want Invalid", err)
	}
}

// yamlMarshal encodes without validating, to produce bad documents.
func yamlMarshal(d *Document) ([]byte, error) { return yaml.Marshal(d) }

func TestTrust(t *testing.T) {
	d := testDocument(t)
	dir := filepath.Join(t.TempDir(), "upspin")
	if err := d.Install(dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.FromFile(filepath.Join(dir, ConfigFile))
	if err != nil {
		t.Fatal(err)
	}

	// The anchors pinned by the identity gather back, for all domains or one.
	tr, err := GatherTrust(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Anchors) != 1 || !reflect.DeepEqual(tr.Anchors[0].Domains, []string{"example.com", "example.net"}) {
		t.Fatalf("GatherTrust: %+v", tr.Anchors)
	}
	one, err := GatherTrust(cfg, "example.net")
	if err != nil || len(one.Anchors) != 1 || !reflect.DeepEqual(one.Anchors[0].Domains, []string{"example.net"}) {
		t.Errorf("GatherTrust(example.net): %+v, %v", one, err)
	}
	if _, err := GatherTrust(cfg, "example.org"); !errors.Match(errors.E(errors.NotExist), err) {
		t.Errorf("GatherTrust of an unpinned domain: %v", err)
	}

	// Both forms parse back to the same thing, and the compact form is
	// distinguishable from an identity.
	plain, err := tr.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	compact, err := tr.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(compact, TrustPrefix) {
		t.Fatalf("compact trust %q", compact)
	}
	for _, in := range [][]byte{plain, []byte(compact + "\n")} {
		back, err := ParseTrust(in)
		if err != nil {
			t.Fatalf("ParseTrust: %v", err)
		}
		if !reflect.DeepEqual(back, tr) {
			t.Errorf("ParseTrust differs:\n%+v\nwant\n%+v", back, tr)
		}
	}
	identity, _ := d.Encode()
	if _, err := ParseTrust([]byte(identity)); !errors.Match(errors.E(errors.Invalid), err) {
		t.Errorf("ParseTrust of an identity: %v, want Invalid", err)
	}
	if _, err := ParseTrust([]byte("anchors: []\n")); !errors.Match(errors.E(errors.Invalid), err) {
		t.Errorf("ParseTrust of no anchors: %v, want Invalid", err)
	}
	if desc := tr.Describe(); !strings.Contains(desc, "example.com, example.net: "+anchor+"\n  SHA256:") {
		t.Errorf("Describe:\n%s", desc)
	}

	// Installing into a fresh keydir pins the anchors there.
	keydir := filepath.Join(t.TempDir(), "keys")
	if err := tr.Install(keydir); err != nil {
		t.Fatal(err)
	}
	domains, err := trust.ListAnchors(keydir)
	if err != nil || !reflect.DeepEqual(domains, []string{"example.com", "example.net"}) {
		t.Errorf("installed domains %v, %v", domains, err)
	}

	// One's own record offered as an anchor, for one's own domain by
	// default or for others by name.
	self, err := SelfTrust(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(self.Anchors) != 1 || !reflect.DeepEqual(self.Anchors[0].Domains, []string{"example.com"}) ||
		!strings.Contains(self.Anchors[0].Record, "name: "+alice+"\n") ||
		!strings.Contains(self.Anchors[0].Record, strings.Fields(d.PublicKey)[2]) {
		t.Errorf("SelfTrust: %+v", self.Anchors)
	}
	self, err = SelfTrust(cfg, "example.org", "example.net")
	if err != nil || len(self.Anchors) != 1 || !reflect.DeepEqual(self.Anchors[0].Domains, []string{"example.org", "example.net"}) {
		t.Errorf("SelfTrust with domains: %+v, %v", self, err)
	}
}
