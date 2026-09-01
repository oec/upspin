// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package remote

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"upspin.io/config"
	"upspin.io/test/testutil"
	"upspin.io/upspin"
)

// serve starts a TLS server on the loopback address that answers every request
// with the given handler, and returns a KeyServer dialed to it. The certificate
// is the one the rpc tests use, and the configuration trusts it.
func serve(t *testing.T, h http.HandlerFunc) upspin.KeyServer {
	t.Helper()
	certDir := testutil.Repo("rpc", "testdata")
	cert, err := tls.LoadX509KeyPair(filepath.Join(certDir, "cert.pem"), filepath.Join(certDir, "key.pem"))
	if err != nil {
		t.Fatalf("loading the test certificate: %v", err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// The certificate names localhost, so the address must too.
	addr := upspin.NetAddr("localhost:" + strings.TrimPrefix(srv.Listener.Addr().String(), "127.0.0.1:"))
	cfg := config.SetUserName(config.New(), "ann@example.com")
	cfg = config.SetValue(cfg, "tlscerts", certDir)
	svc, err := (&remote{}).Dial(cfg, upspin.Endpoint{Transport: upspin.Remote, NetAddr: addr})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	return svc.(upspin.KeyServer)
}

// TestLookupOfEmptyReply covers what is listening at the address named as a key
// server not being one. An empty body decodes to a KeyLookupResponse that
// carries neither a user nor an error, and the record was passed on as it
// stood: a nil pointer, dereferenced by the first thing to read a field from
// it. A client crashed on what a stranger on the network chose to return.
func TestLookupOfEmptyReply(t *testing.T) {
	ks := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // And no body at all.
	})
	u, err := ks.Lookup("ann@example.com")
	if err == nil {
		t.Fatalf("Lookup returned %v; want an error", u)
	}
	if !strings.Contains(err.Error(), "neither a user record nor an error") {
		t.Errorf("Lookup error = %v; want it to say the reply held nothing", err)
	}
}

// TestLookupOfErrorPage covers the other half: an HTTP error from whatever is
// listening, which is not a reply in this protocol and must not be decoded as
// one.
func TestLookupOfErrorPage(t *testing.T) {
	ks := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no such page", http.StatusNotFound)
	})
	if u, err := ks.Lookup("ann@example.com"); err == nil {
		t.Fatalf("Lookup returned %v; want an error", u)
	} else if !strings.Contains(err.Error(), "404") {
		t.Errorf("Lookup error = %v; want it to name the HTTP status", err)
	}
}
