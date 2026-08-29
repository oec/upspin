// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trust

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"upspin.io/config"
	"upspin.io/upspin"
)

// serve installs a fake HTTP transport that answers only the given URLs, and a
// fake SRV lookup that answers only for the given domain, and undoes both when
// the test ends. Nothing here touches the network.
func serve(t *testing.T, srv map[string][]*net.SRV, pages map[string]string) {
	t.Helper()
	oldSRV, oldClient := lookupSRV, httpClientFor
	t.Cleanup(func() { lookupSRV, httpClientFor = oldSRV, oldClient })

	lookupSRV = func(service, proto, name string) (string, []*net.SRV, error) {
		if service != "upspin" || proto != "tcp" {
			t.Errorf("lookupSRV(%q, %q, ...); want (upspin, tcp, ...)", service, proto)
		}
		if s, ok := srv[name]; ok {
			return "", s, nil
		}
		return "", nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	client := &http.Client{Transport: fakeTransport(pages)}
	httpClientFor = func(upspin.Config) (*http.Client, error) { return client, nil }
}

type fakeTransport map[string]string

func (f fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body, ok := f[r.URL.String()]
	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Status:     "404 Not Found",
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    r,
		}, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    r,
	}, nil
}

// anchored returns a key directory with ann pinned as the trust anchor for
// example.com, and an attested record for carol@example.com signed by her.
func anchored(t *testing.T) (dir string, record []byte) {
	t.Helper()
	dir = t.TempDir()
	f, _ := anchorFactotum(t)
	if err := WriteAnchor(dir, "example.com", annUser()); err != nil {
		t.Fatal(err)
	}
	record, err := Sign(f, attestedUser()) // carol@example.com
	if err != nil {
		t.Fatal(err)
	}
	return dir, record
}

func bundleOf(t *testing.T, records ...[]byte) string {
	t.Helper()
	data, err := Bundle(records)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestDiscoveryConfig(t *testing.T) {
	base := config.SetUserName(config.New(), "ann@example.com")
	if Discovery(nil) {
		t.Error("Discovery(nil) = true")
	}
	if Discovery(base) {
		t.Errorf("Discovery is on with no %s; it must be opt-in", DiscoveryConfigKey)
	}
	for _, on := range []string{"y", "yes", "true", "TRUE", "1", "on"} {
		if !Discovery(config.SetValue(base, DiscoveryConfigKey, on)) {
			t.Errorf("Discovery(%q) = false", on)
		}
	}
	for _, off := range []string{"", "n", "no", "false", "0", "maybe"} {
		if Discovery(config.SetValue(base, DiscoveryConfigKey, off)) {
			t.Errorf("Discovery(%q) = true", off)
		}
	}
}

func TestBundle(t *testing.T) {
	f, key := anchorFactotum(t)
	one, err := Sign(f, attestedUser())
	if err != nil {
		t.Fatal(err)
	}
	other := attestedUser()
	other.Name = "dave@example.com"
	two, err := Sign(f, other)
	if err != nil {
		t.Fatal(err)
	}

	data, err := Bundle([][]byte{one, two})
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	got, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ParseBundle returned %d records; want 2", len(got))
	}
	// A signature covers the bytes it was made over, so a bundle must
	// preserve them exactly or nothing in it will verify.
	if !bytes.Equal(got[0], one) || !bytes.Equal(got[1], two) {
		t.Error("ParseBundle did not return the records byte for byte")
	}
	for i, record := range got {
		if _, err := Verify(record, key); err != nil {
			t.Errorf("record %d does not verify after bundling: %v", i, err)
		}
	}
}

func TestDiscoverBundle(t *testing.T) {
	dir, record := anchored(t)
	serve(t,
		map[string][]*net.SRV{
			"example.com": {{Target: "keys.example.com.", Port: 443}},
		},
		map[string]string{
			"https://keys.example.com" + WellKnownPath: bundleOf(t, record),
		})

	var d discovery
	got := d.lookup(config.New(), dir, "carol@example.com")
	if got == nil {
		t.Fatal("lookup found nothing")
	}
	if got.PublicKey != bobKey {
		t.Errorf("lookup = %q; want the published key", got.PublicKey)
	}

	// A user the domain does not publish is not found, and the miss is
	// remembered rather than fetched again.
	if u := d.lookup(config.New(), dir, "nobody@example.com"); u != nil {
		t.Errorf("lookup of an unpublished user = %v; want nil", u)
	}
}

// TestDiscoverWellKnown checks the case that needs no DNS record at all: a
// domain that serves its records from its own web server.
func TestDiscoverWellKnown(t *testing.T) {
	dir, record := anchored(t)
	serve(t, nil, map[string]string{
		"https://example.com" + WellKnownPath: bundleOf(t, record),
	})

	var d discovery
	if got := d.lookup(config.New(), dir, "carol@example.com"); got == nil {
		t.Fatal("lookup found nothing at the well-known path")
	}
}

// TestDiscoverSingleRecord checks the fallback for a domain that publishes one
// file per user rather than a bundle.
func TestDiscoverSingleRecord(t *testing.T) {
	dir, record := anchored(t)
	serve(t, nil, map[string]string{
		// No bundle at the base; only the per-user file.
		"https://example.com" + WellKnownPath + "/carol@example.com": string(record),
	})

	var d discovery
	if got := d.lookup(config.New(), dir, "carol@example.com"); got == nil {
		t.Fatal("lookup did not fall back to the per-user record")
	}
}

// TestDiscoveryTrustsOnlyTheAnchor is the point of the whole exercise. An
// attacker who can answer DNS, or who holds a certificate for a host of their
// choosing, can decide which server is asked. They must still not be able to
// decide what the answer is.
func TestDiscoveryTrustsOnlyTheAnchor(t *testing.T) {
	dir := t.TempDir()
	if err := WriteAnchor(dir, "example.com", annUser()); err != nil {
		t.Fatal(err)
	}
	// A record signed by a key that is not example.com's anchor.
	forged, err := Sign(otherFactotum(t), attestedUser())
	if err != nil {
		t.Fatal(err)
	}
	// An honest record, but with no attestation at all.
	plain, _, err := Split(forged)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("hostile SRV target", func(t *testing.T) {
		// DNS sends the lookup to a host in another domain entirely,
		// which answers with a well-formed but wrongly signed record.
		serve(t,
			map[string][]*net.SRV{
				"example.com": {{Target: "keys.attacker.example.", Port: 443}},
			},
			map[string]string{
				"https://keys.attacker.example" + WellKnownPath: bundleOf(t, forged),
			})
		var d discovery
		if got := d.lookup(config.New(), dir, "carol@example.com"); got != nil {
			t.Errorf("lookup accepted %v from a host named by DNS", got.Name)
		}
	})

	t.Run("unattested record", func(t *testing.T) {
		serve(t, nil, map[string]string{
			"https://example.com" + WellKnownPath: bundleOf(t, plain),
		})
		var d discovery
		if got := d.lookup(config.New(), dir, "carol@example.com"); got != nil {
			t.Errorf("lookup accepted an unattested record: %v", got.Name)
		}
	})

	t.Run("record for another domain", func(t *testing.T) {
		// example.com's anchor also happens to be pinned for
		// other.example, but a server for one domain must not be able
		// to answer for another.
		if err := WriteAnchor(dir, "other.example", annUser()); err != nil {
			t.Fatal(err)
		}
		f, _ := anchorFactotum(t)
		elsewhere := attestedUser()
		elsewhere.Name = "carol@other.example"
		record, err := Sign(f, elsewhere)
		if err != nil {
			t.Fatal(err)
		}
		serve(t, nil, map[string]string{
			"https://example.com" + WellKnownPath: bundleOf(t, record),
		})
		var d discovery
		if got := d.lookup(config.New(), dir, "carol@other.example"); got != nil {
			t.Errorf("example.com answered for %v", got.Name)
		}
	})
}

// TestDiscoveryNeedsKeyDir checks that discovery is inert without a key
// directory: with no anchors pinned, nothing discovered could be checked.
func TestDiscoveryNeedsKeyDir(t *testing.T) {
	_, record := anchored(t)
	serve(t, nil, map[string]string{
		"https://example.com" + WellKnownPath: bundleOf(t, record),
	})
	var d discovery
	if got := d.lookup(config.New(), "", "carol@example.com"); got != nil {
		t.Errorf("lookup = %v with no key directory; want nil", got)
	}
}

// TestBaseURLs covers the shape of the URLs tried, including the port and the
// order: what DNS names first, then the domain itself.
func TestBaseURLs(t *testing.T) {
	serve(t, map[string][]*net.SRV{
		"example.com": {
			{Target: "a.example.com.", Port: 443},
			{Target: "b.example.com.", Port: 8443},
			{Target: ".", Port: 443}, // "no service here" (RFC 2782)
		},
	}, nil)

	got := baseURLs("example.com")
	want := []string{
		"https://a.example.com" + WellKnownPath,
		"https://b.example.com:8443" + WellKnownPath,
		"https://example.com" + WellKnownPath,
	}
	if len(got) != len(want) {
		t.Fatalf("baseURLs = %v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("baseURLs[%d] = %q; want %q", i, got[i], want[i])
		}
	}

	// A domain with no SRV record is still asked directly.
	if got := baseURLs("nodns.example"); len(got) != 1 || got[0] != "https://nodns.example"+WellKnownPath {
		t.Errorf("baseURLs with no SRV = %v", got)
	}
}
