// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package trust implements a KeyServer that answers lookups from a directory
// of locally pinned user records before consulting another KeyServer.
//
// An upspin.User record is not signed on the wire, so whatever a key server
// returns is taken on faith, including the public key to which a client will
// wrap the keys of the files it shares. A key server is therefore an
// unconditionally trusted party in a system that is otherwise end-to-end
// encrypted. Pinning a record locally removes that trust for that user: the
// pinned record is used as it stands and the key server is not consulted.
//
// The pinned records live in the directory named by the "keydir" value in the
// configuration, one file per user, named for the user and holding the YAML
// encoding of an upspin.User, which is the form printed by "upspin user":
//
//	name: ann@example.com
//	dirs:
//	- remote,dir.example.com:443
//	stores:
//	- remote,store.example.com:443
//	publickey: |
//	  p256
//	  1234...
//	  5678...
//
// A record is read from disk on each lookup rather than cached, so that adding
// or correcting a pin takes effect immediately, without restarting a server
// whose key directory is in effect its admission list. The files are small and
// the operating system's page cache makes the read cheap.
//
// Verifying every user's key by hand does not scale past a handful of them, so
// a record may instead be attested: signed by a key that the reader has pinned
// as entitled to speak for a domain, in the trust-anchors subdirectory of the
// key directory. Pinning one such anchor for a domain is then enough to accept
// records for every user in it. Attestations are checked at the boundary, by
// Accept, when a record arrives from somewhere the reader does not control;
// what is already in the key directory is trusted because it is there.
//
// # The order of a lookup
//
// A lookup consults up to four sources and returns the first answer it finds.
// The order is the order of authority, so that nothing below can shadow what
// is above it:
//
//  1. The pinned key directory, "keydir". It is read from disk on every
//     lookup, so nothing else is consulted for a user who is pinned, and no
//     network is touched. A record that is present but unusable, whether
//     damaged or holding some other user's name, fails the lookup rather than
//     falling through: falling through would let a tampered file be replaced
//     silently by whatever a key server chose to return.
//
//  2. The delegated key sets, "keysets": directories of records published in
//     someone's Upspin name space. A record from one is used only if Accept
//     passes it, so the owner of a set carries records without vouching for
//     them. The sets are read as a snapshot and refreshed on a timer, not on
//     each lookup. Where two of them publish different records for one user,
//     the set named first in the configuration answers; "upspin keytrust
//     -check" reports the disagreement, which a lookup cannot.
//
//  3. The wrapped key server. Its answer may carry an attestation, which is a
//     signed copy of the record rather than a signature over the one the
//     server sent. If that copy verifies against the pinned anchors it is
//     used and the server's own fields are discarded, not compared, so that
//     nothing outside the signed bytes is used at all and a key server that
//     attests to what it serves is no longer a trusted party. An answer with
//     no attestation, or one for a domain with no anchor pinned, is believed
//     as it always was.
//
//  4. Discovery, "keydiscovery": the records a domain publishes for itself
//     over DNS and HTTPS. Used only through Accept, so neither DNS nor the
//     server that answers it is trusted to say what a key is, only which
//     server to ask. Discovery answers for the users the key server does not
//     know, which is every user when the configuration names no key server.
//
// The key server precedes discovery because it is named in the configuration,
// deliberately and for a reason its owner had, where discovery is a standing
// willingness to ask any domain about its own users. The cost of that order is
// that an unattested answer from the key server is preferred to an attested
// one from the user's own domain. What removes that cost is pinning: a pinned
// record outranks both, and a key server that serves attested records has its
// answer checked against the same anchors, so a domain that wants to be
// believed on its own terms should put its records where they will be checked
// rather than rely on being asked last.
//
// A key server that fails to answer is not an error while discovery may still
// answer, but one that offers an attestation that does not verify is: that is
// hostile rather than absent, and the lookup fails there rather than looking
// elsewhere.
//
// The key sets and discovery both rest on the anchors in the key directory, so
// a configuration that names no keydir resolves every user through the key
// server: there is nothing for a published record to be checked against, and
// neither source is consulted.
//
// A configuration that names no key server, its key endpoint unassigned,
// answers for its own user from itself, after the pins and before the sets. The record holds nothing that is not
// in the configuration already: the user name, the two endpoints, and the
// public half of the factotum's key pair. Every operation on a user's own tree
// begins by resolving her own name, so without this she would have to pin
// herself in order to name herself. A pinned record for her still wins, and a
// configuration that does name a key server asks it as before, which is what
// lets "upspin user" report a configuration that disagrees with the record the
// server holds.
//
// It precedes the sets because reading a set is an Upspin read, which
// authenticates, which needs this same key. A server whose own user is not
// pinned would go to the network to learn a key it is holding, and where the
// set lives in a tree that server serves, it would call itself to do it, while
// still holding what the inner call needs.
//
// Two properties follow from the order rather than from any one source. This
// package must be registered as the outermost KeyServer wrapper, enclosing
// key/usercache rather than enclosed by it, or a cached answer from a key
// server could shadow a pinned record. And a pinned record contradicted by an
// attested record already in memory, from a set or from discovery, fails the
// lookup instead of answering: nothing in Upspin pushes a key change, so a pin
// can outlive the key it names, and the alternative is to wrap files to a key
// their reader no longer holds and tell nobody.
package trust // import "upspin.io/key/trust"

import (
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"

	yaml "gopkg.in/yaml.v2"

	"upspin.io/errors"
	"upspin.io/factotum"
	"upspin.io/upspin"
	"upspin.io/user"
	"upspin.io/valid"
)

// ConfigKey is the configuration file key naming the directory that holds
// pinned user records.
const ConfigKey = "keydir"

// Dir returns the pinned key directory named by the configuration, or the
// empty string if the configuration names none. A leading tilde is replaced by
// the home directory of the user running the process.
func Dir(cfg upspin.Config) (string, error) {
	const op errors.Op = "key/trust.Dir"
	if cfg == nil {
		return "", nil
	}
	dir := strings.TrimSpace(cfg.Value(ConfigKey))
	if dir == "" {
		return "", nil
	}
	if dir == "~" || strings.HasPrefix(dir, "~"+string(filepath.Separator)) {
		home, err := homedir()
		if err != nil {
			return "", errors.E(op, err)
		}
		dir = filepath.Join(home, dir[1:])
	}
	if !filepath.IsAbs(dir) {
		return "", errors.E(op, errors.Invalid, errors.Errorf("%s must be an absolute path; have %q", ConfigKey, dir))
	}
	return dir, nil
}

// CheckKeyEndpoint reports an error if the configuration can resolve nobody
// but itself: that is, if its key endpoint is unassigned and it names no
// directory of pinned records. An unassigned key endpoint is otherwise
// legitimate, and means that other users are resolved only from that
// directory.
func CheckKeyEndpoint(cfg upspin.Config) error {
	const op errors.Op = "key/trust.CheckKeyEndpoint"
	if cfg.KeyEndpoint().Transport != upspin.Unassigned {
		return nil
	}
	dir, err := Dir(cfg)
	if err != nil {
		return errors.E(op, err)
	}
	if dir == "" {
		return errors.E(op, errors.Invalid,
			"key endpoint cannot be unassigned without a "+ConfigKey)
	}
	return nil
}

// homedir reports the home directory of the user running this process. It
// mirrors config.Homedir, which this package does not import because config
// sits above the key layer.
func homedir() (string, error) {
	u, err := osuser.Current()
	// osuser.Current may return an error even when it returns a usable
	// user; only a nil user is fatal.
	if u == nil {
		e := errors.Str("lookup of current user failed")
		if err != nil {
			e = errors.Errorf("%v: %v", e, err)
		}
		return "", e
	}
	if u.HomeDir == "" {
		return "", errors.E(errors.NotExist, "user home directory not found")
	}
	return u.HomeDir, nil
}

// fileName returns the name of the file holding the pinned record for name,
// within dir.
func fileName(op errors.Op, dir string, name upspin.UserName) (string, upspin.UserName, error) {
	clean, err := user.Clean(name)
	if err != nil {
		return "", "", errors.E(op, name, err)
	}
	// A valid user name can never contain a path separator, but this value
	// is about to become a file name, so do not take that on trust.
	if filepath.Base(string(clean)) != string(clean) {
		return "", "", errors.E(op, name, errors.Invalid, "user name is not a valid file name")
	}
	return filepath.Join(dir, string(clean)), clean, nil
}

// Read returns the pinned record for name held in dir. If there is no such
// record it returns an error of kind errors.NotExist. A record that is present
// but unusable is an error, never a silent absence: a corrupt or tampered pin
// must not quietly fall through to a key server.
//
// A pinned record may carry an attestation, which Read parses past but does
// not check. A record is trusted because it is pinned; an attestation is what
// justifies pinning it in the first place, and is checked then, by Accept.
func Read(dir string, name upspin.UserName) (*upspin.User, error) {
	const op errors.Op = "key/trust.Read"
	file, clean, err := fileName(op, dir, name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return nil, errors.E(op, clean, errors.NotExist, "no pinned key")
	}
	if err != nil {
		return nil, errors.E(op, clean, errors.IO, err)
	}
	record, _, err := Split(data)
	if err != nil {
		return nil, errors.E(op, clean, errors.Errorf("%s: %v", file, err))
	}
	u := new(upspin.User)
	if err := yaml.Unmarshal(record, u); err != nil {
		return nil, errors.E(op, clean, errors.Invalid, errors.Errorf("parsing %s: %v", file, err))
	}
	if u.Name != clean {
		return nil, errors.E(op, clean, errors.Invalid,
			errors.Errorf("%s holds a record for %q", file, u.Name))
	}
	if err := Validate(u); err != nil {
		return nil, errors.E(op, clean, errors.Errorf("%s: %v", file, err))
	}
	return u, nil
}

// ReadRaw returns the pinned record for name as it is stored, including any
// attestation, so that it can be passed on to someone else exactly as it
// arrived. If there is no such record it returns an error of kind
// errors.NotExist.
func ReadRaw(dir string, name upspin.UserName) ([]byte, error) {
	const op errors.Op = "key/trust.ReadRaw"
	file, clean, err := fileName(op, dir, name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return nil, errors.E(op, clean, errors.NotExist, "no pinned key")
	}
	if err != nil {
		return nil, errors.E(op, clean, errors.IO, err)
	}
	return data, nil
}

// Validate reports whether u is fit to be pinned. It is stricter than
// valid.User, which does not inspect the public key.
func Validate(u *upspin.User) error {
	const op errors.Op = "key/trust.Validate"
	if err := valid.User(u); err != nil {
		return errors.E(op, err)
	}
	if u.PublicKey == "" {
		return errors.E(op, u.Name, errors.Invalid, "no public key")
	}
	if _, err := factotum.ParsePublicKey(u.PublicKey); err != nil {
		return errors.E(op, u.Name, errors.Invalid, err)
	}
	if len(u.Dirs) == 0 {
		return errors.E(op, u.Name, errors.Invalid, "no directory endpoints")
	}
	return nil
}

// Write pins u in dir, replacing any record already there. The directory is
// created if it does not exist.
func Write(dir string, u *upspin.User) error {
	const op errors.Op = "key/trust.Write"
	if err := Validate(u); err != nil {
		return errors.E(op, err)
	}
	rec := *u
	clean, err := user.Clean(u.Name)
	if err != nil {
		return errors.E(op, u.Name, err)
	}
	rec.Name = clean
	data, err := yaml.Marshal(rec)
	if err != nil {
		return errors.E(op, clean, err)
	}
	return Pin(dir, data)
}

// Pin stores data, a user record that may carry an attestation, as the pinned
// record for the user it names, replacing any record already there. The record
// is validated, but the bytes are stored as they stand, so that an attestation
// is kept along with the record it vouches for. The directory is created if it
// does not exist.
func Pin(dir string, data []byte) error {
	const op errors.Op = "key/trust.Pin"
	record, _, err := Split(data)
	if err != nil {
		return errors.E(op, err)
	}
	u := new(upspin.User)
	if err := yaml.Unmarshal(record, u); err != nil {
		return errors.E(op, errors.Invalid, errors.Errorf("parsing record: %v", err))
	}
	if err := Validate(u); err != nil {
		return errors.E(op, err)
	}
	file, clean, err := fileName(op, dir, u.Name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.E(op, errors.IO, err)
	}
	if err := os.WriteFile(file, data, 0600); err != nil {
		return errors.E(op, clean, errors.IO, err)
	}
	return nil
}

// Remove deletes the pinned record for name from dir.
func Remove(dir string, name upspin.UserName) error {
	const op errors.Op = "key/trust.Remove"
	file, clean, err := fileName(op, dir, name)
	if err != nil {
		return err
	}
	if err := os.Remove(file); err != nil {
		if os.IsNotExist(err) {
			return errors.E(op, clean, errors.NotExist, "no pinned key")
		}
		return errors.E(op, clean, errors.IO, err)
	}
	return nil
}

// List returns the names of the users pinned in dir, sorted. A directory that
// does not exist holds no pins and is not an error.
func List(dir string) ([]upspin.UserName, error) {
	const op errors.Op = "key/trust.List"
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.E(op, errors.IO, err)
	}
	var names []upspin.UserName
	for _, e := range entries {
		if e.IsDir() {
			// Subdirectories hold other kinds of record.
			continue
		}
		name, err := user.Clean(upspin.UserName(e.Name()))
		if err != nil {
			// Not a user name; not ours.
			continue
		}
		names = append(names, name)
	}
	// os.ReadDir returns entries sorted by file name, and user.Clean only
	// lowercases the domain, so the result is already in order.
	return names, nil
}
