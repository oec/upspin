// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trust

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	yaml "gopkg.in/yaml.v2"

	"upspin.io/errors"
	"upspin.io/log"
	"upspin.io/rpc"
	"upspin.io/upspin"
)

// Discovery finds the records a domain publishes for its own users, without
// any prior arrangement between the reader and that domain. A domain says
// where its records are with a DNS SRV record,
//
//	_upspin._tcp.example.com. 86400 IN SRV 10 60 443 keys.example.com.
//
// and serves them over HTTPS beneath a well-known path, either as a bundle of
// every record it publishes,
//
//	https://keys.example.com/.well-known/upspin/keys
//
// or one file per user, named for the user, under the same path:
//
//	https://keys.example.com/.well-known/upspin/keys/alice@example.com
//
// A domain that publishes records on its own web server need not run anything
// else, and need not publish an SRV record either: with none, the well-known
// path on the domain itself is tried.
//
// Nothing here trusts DNS, the server that answers, or its certificate. Every
// record must be attested and must verify against a trust anchor the reader
// has pinned for the domain in the *user's own name*, never for the host the
// SRV record happened to name. That is what makes discovery safe to do at all:
// an attacker who controls a resolver, or who obtains a certificate for a host
// of their choosing, can redirect the fetch and still not change a key. It is
// also why discovery cannot use a key server's RPC interface, whose reply
// carries no signature: see the note on ErrNoAttestation below.

// DiscoveryConfigKey enables discovery of published records over DNS and
// HTTPS. It is off unless the configuration sets it.
const DiscoveryConfigKey = "keydiscovery"

// WellKnownPath is the path beneath which a domain publishes its records,
// as registered use of the /.well-known/ prefix (RFC 8615).
const WellKnownPath = "/.well-known/upspin/keys"

// maxBundleSize bounds what will be read from a server that may not be
// friendly.
const maxBundleSize = 1 << 24 // 16MB

// lookupSRV is the DNS lookup used to find where a domain publishes its
// records. It aliases net.LookupSRV except in tests.
var lookupSRV = net.LookupSRV

// httpClientFor returns the HTTP client used to fetch published records. It is
// a variable so that tests can supply a client that trusts a test server.
var httpClientFor = func(cfg upspin.Config) (*http.Client, error) {
	// Honour the tlscerts setting, so that a domain serving its records
	// under a certificate of its own can be reached without the public
	// certificate authorities. This is defence in depth: the attestation
	// on a record, not the transport, is what makes it believable.
	pool, err := rpc.CertPoolFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}, nil
}

// Discovery reports whether the configuration asks for records to be
// discovered over DNS and HTTPS.
func Discovery(cfg upspin.Config) bool {
	if cfg == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Value(DiscoveryConfigKey))) {
	case "y", "yes", "true", "1", "on":
		return true
	}
	return false
}

// Bundle returns the published form of a set of attested records: a YAML
// sequence whose elements are the records themselves, each preserved exactly,
// since a signature covers the bytes it was made over.
func Bundle(records [][]byte) ([]byte, error) {
	const op errors.Op = "key/trust.Bundle"
	texts := make([]string, 0, len(records))
	for _, r := range records {
		texts = append(texts, string(r))
	}
	data, err := yaml.Marshal(texts)
	if err != nil {
		return nil, errors.E(op, err)
	}
	return data, nil
}

// ParseBundle returns the records in a published bundle.
func ParseBundle(data []byte) ([][]byte, error) {
	const op errors.Op = "key/trust.ParseBundle"
	var texts []string
	if err := yaml.Unmarshal(data, &texts); err != nil {
		return nil, errors.E(op, errors.Invalid, errors.Errorf("parsing bundle: %v", err))
	}
	records := make([][]byte, 0, len(texts))
	for _, t := range texts {
		records = append(records, []byte(t))
	}
	return records, nil
}

// discovery holds what has been discovered, one entry per domain.
type discovery struct {
	mu      sync.Mutex
	domains map[string]*published
}

// published is what a single domain has been found to publish. A name present
// with a nil value has been asked for and not found, so that a user who does
// not exist is not fetched again before the next refresh.
type published struct {
	users   map[upspin.UserName]*upspin.User
	lastTry time.Time
	busy    bool
}

// lookup returns the record a domain publishes for name, or nil if it
// publishes none that can be accepted. It never returns an error: discovery is
// a last resort before the wrapped key server, and a domain that publishes
// nothing, or nothing believable, is simply a domain with no answer.
func (d *discovery) lookup(cfg upspin.Config, keyDir string, name upspin.UserName) *upspin.User {
	domain, err := domainOf(name)
	if err != nil {
		return nil
	}
	if keyDir == "" {
		// Without a key directory there are no anchors, so nothing
		// discovered could be verified against anything.
		return nil
	}

	d.mu.Lock()
	if d.domains == nil {
		d.domains = make(map[string]*published)
	}
	p := d.domains[domain]
	if p == nil {
		p = &published{users: make(map[upspin.UserName]*upspin.User)}
		d.domains[domain] = p
	}

	// Refresh the whole of what the domain publishes if it is time to, and
	// no other lookup is already doing so.
	due := p.lastTry.IsZero() || time.Since(p.lastTry) > refreshInterval
	if !p.busy && due {
		p.busy = true
		p.lastTry = time.Now()
		d.mu.Unlock()

		users := fetchDomain(cfg, keyDir, domain, name)

		d.mu.Lock()
		if users != nil {
			p.users = users
		}
		p.busy = false
	}
	u, asked := p.users[name]
	d.mu.Unlock()
	if asked {
		return u
	}

	// The bundle did not name this user, or there was no bundle. Ask for
	// the one record.
	d.mu.Lock()
	if p.busy {
		d.mu.Unlock()
		return nil
	}
	p.busy = true
	d.mu.Unlock()

	u = fetchUser(cfg, keyDir, domain, name)

	d.mu.Lock()
	p.users[name] = u // Remember a miss too, as a nil entry.
	p.busy = false
	d.mu.Unlock()
	return u
}

// peek returns the record discovery has already found for name, if any. It
// never fetches, so it is free to call on a lookup that has already been
// answered from the pinned key directory.
func (d *discovery) peek(name upspin.UserName) *upspin.User {
	domain, err := domainOf(name)
	if err != nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.domains[domain]
	if p == nil {
		return nil
	}
	return p.users[name]
}

// fetchDomain returns everything a domain publishes in a bundle, or nil if it
// publishes no bundle that can be read.
func fetchDomain(cfg upspin.Config, keyDir, domain string, want upspin.UserName) map[upspin.UserName]*upspin.User {
	const op errors.Op = "key/trust.fetchDomain"
	for _, base := range baseURLs(domain) {
		data, err := fetch(cfg, base)
		if err != nil {
			log.Debug.Printf("%s: %s: %v", op, base, err)
			continue
		}
		records, err := ParseBundle(data)
		if err != nil {
			log.Error.Printf("%s: %s: %v", op, base, err)
			continue
		}
		users := make(map[upspin.UserName]*upspin.User)
		for _, record := range records {
			u, err := Accept(keyDir, record)
			if err != nil {
				log.Error.Printf("%s: %s: %v", op, base, err)
				continue
			}
			// Accept has checked the attestation against the
			// anchor pinned for the record's own domain, so a
			// bundle served anywhere can only carry records for
			// domains the reader has already decided to trust.
			// Refuse the rest so that one domain's server cannot
			// fill the cache with another's users.
			if got, _ := domainOf(u.Name); got != domain {
				log.Error.Printf("%s: %s: holds a record for %s, of another domain", op, base, u.Name)
				continue
			}
			users[u.Name] = u
		}
		return users
	}
	return nil
}

// fetchUser returns the single record a domain publishes for name, or nil.
func fetchUser(cfg upspin.Config, keyDir, domain string, name upspin.UserName) *upspin.User {
	const op errors.Op = "key/trust.fetchUser"
	for _, base := range baseURLs(domain) {
		data, err := fetch(cfg, base+"/"+url.PathEscape(string(name)))
		if err != nil {
			log.Debug.Printf("%s: %s: %v", op, name, err)
			continue
		}
		u, err := Accept(keyDir, data)
		if err != nil {
			log.Error.Printf("%s: %s: %v", op, name, err)
			continue
		}
		if u.Name != name {
			log.Error.Printf("%s: %s: holds a record for %s", op, name, u.Name)
			continue
		}
		return u
	}
	return nil
}

// baseURLs returns the URLs beneath which a domain may publish its records, in
// the order they should be tried: those named by the domain's SRV records
// first, then the domain itself, which needs no DNS record of its own.
func baseURLs(domain string) []string {
	var urls []string
	_, srvs, err := lookupSRV("upspin", "tcp", domain)
	if err == nil {
		for _, srv := range srvs {
			host := strings.TrimSuffix(srv.Target, ".")
			if host == "" {
				// A single target of "." says the domain
				// explicitly offers no service (RFC 2782).
				continue
			}
			if srv.Port != 443 {
				host = net.JoinHostPort(host, strconv.Itoa(int(srv.Port)))
			}
			urls = append(urls, "https://"+host+WellKnownPath)
		}
	}
	return append(urls, "https://"+domain+WellKnownPath)
}

// fetch returns the body of an HTTPS GET, bounded in size.
func fetch(cfg upspin.Config, url string) ([]byte, error) {
	const op errors.Op = "key/trust.fetch"
	client, err := httpClientFor(cfg)
	if err != nil {
		return nil, errors.E(op, err)
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, errors.E(op, errors.IO, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.E(op, errors.NotExist, errors.Errorf("%s: %s", url, resp.Status))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleSize))
	if err != nil {
		return nil, errors.E(op, errors.IO, err)
	}
	return data, nil
}
