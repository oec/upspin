// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trust

import (
	"path"
	"strings"
	"sync"
	"time"

	yaml "gopkg.in/yaml.v2"

	"upspin.io/bind"
	"upspin.io/client/clientutil"
	"upspin.io/errors"
	"upspin.io/log"
	upath "upspin.io/path"
	"upspin.io/upspin"
	"upspin.io/user"
)

// A delegated key set is a directory in someone's name space holding user
// records, which the reader has named in the keysets entry of the
// configuration. It is how a key reaches a reader who was not handed it: the
// owner of the set publishes records, and readers who have named the set pick
// them up. It is also the only channel by which a key that has changed can
// reach the people holding the old one, since nothing pushes.
//
// A record in a delegated set is used only if it is attested and the
// attestation verifies against a trust anchor the reader has pinned for the
// record's domain. Accepting an unattested record because the set's owner
// offered it would make that owner able to name anyone's key, which is the
// arrangement with a key server that this package exists to end. The owner of
// a set is therefore a carrier, not an authority; to let one person speak for
// a domain's users, pin them as that domain's anchor.
//
// The set is read as a snapshot and refreshed at an interval, rather than
// being consulted afresh on each lookup. That keeps lookups off the network,
// and, more importantly, keeps them from re-entering: reading a set is itself
// an Upspin read, which needs the key of whoever owns it, so a lookup that
// fetched would call back into this package. While a refresh is running the
// set is not consulted, so those inner lookups fall through to the pinned key
// directory and the wrapped key server, and cannot recurse.

// SetsConfigKey is the configuration file key naming the delegated key sets to
// consult, as a list of Upspin path names.
const SetsConfigKey = "keysets"

// refreshInterval is how often a delegated key set is re-read. It also bounds
// how often a lookup for a user who is in no set will try again.
var refreshInterval = 2 * time.Minute

// Sets returns the delegated key sets named by the configuration, in the order
// given, or nil if it names none.
func Sets(cfg upspin.Config) ([]upspin.PathName, error) {
	const op errors.Op = "key/trust.Sets"
	if cfg == nil {
		return nil, nil
	}
	text := strings.TrimSpace(cfg.Value(SetsConfigKey))
	if text == "" {
		return nil, nil
	}
	var names []string
	if err := yaml.Unmarshal([]byte(text), &names); err != nil {
		// Also accept a single path, unadorned, since one set is the
		// common case and a bare string is what a user will write.
		names = []string{text}
	}
	var sets []upspin.PathName
	for _, name := range names {
		p, err := upath.Parse(upspin.PathName(strings.TrimSpace(name)))
		if err != nil {
			return nil, errors.E(op, errors.Invalid,
				errors.Errorf("%s: %q is not an Upspin path: %v", SetsConfigKey, name, err))
		}
		if p.IsRoot() {
			return nil, errors.E(op, errors.Invalid,
				errors.Errorf("%s: %q names a whole name space, not a directory of keys", SetsConfigKey, name))
		}
		sets = append(sets, p.Path())
	}
	return sets, nil
}

// sets holds the snapshot of the records published in the delegated key sets,
// and the state of the refresh that produces it.
type sets struct {
	paths []upspin.PathName

	mu sync.Mutex
	// users is the current snapshot. It is replaced wholesale, never
	// modified, so a reader may use it after releasing the lock.
	users map[upspin.UserName]*upspin.User
	// lastTry is when a refresh was last begun, successful or not, so that
	// a user who is in no set does not provoke one on every lookup.
	lastTry time.Time
	// refreshing reports whether a refresh is running. While it is, the
	// snapshot is served as it stands and no new refresh begins, which is
	// what keeps the reads a refresh performs from recursing.
	refreshing bool
}

// lookup returns the record published for name in one of the delegated sets,
// refreshing the snapshot first if it is absent or stale. It returns a nil
// user, and no error, if no set publishes an acceptable record for name.
func (s *sets) lookup(cfg upspin.Config, keyDir string, name upspin.UserName) *upspin.User {
	s.mu.Lock()
	users := s.users
	// A refresh is due if none has ever been tried, or if the last attempt
	// was long enough ago. A failed attempt counts, so that a user who is
	// in no set does not provoke one on every lookup.
	due := s.lastTry.IsZero() || time.Since(s.lastTry) > refreshInterval
	if !s.refreshing && due {
		s.refreshing = true
		s.lastTry = time.Now()
		s.mu.Unlock()

		fresh := s.load(cfg, keyDir)

		s.mu.Lock()
		if fresh != nil {
			s.users = fresh
		}
		s.refreshing = false
		users = s.users
	}
	s.mu.Unlock()
	return users[name]
}

// peek returns the record a set publishes for name if the snapshot already
// holds one. It never fetches, so it is free to call on a lookup that has
// already been answered from the pinned key directory.
func (s *sets) peek(name upspin.UserName) *upspin.User {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.users[name]
}

// load reads every delegated set and returns the records it accepts from them,
// or nil if no set could be read at all. Earlier sets win, so that the order
// in the configuration decides between two sets that publish the same user.
func (s *sets) load(cfg upspin.Config, keyDir string) map[upspin.UserName]*upspin.User {
	const op errors.Op = "key/trust.load"
	users := make(map[upspin.UserName]*upspin.User)
	read := false
	for _, set := range s.paths {
		found, err := readSet(cfg, keyDir, set)
		if err != nil {
			// One unreadable set must not discard the others, nor
			// the snapshot already in hand, so note it and go on.
			log.Error.Printf("%s: %s: %v", op, set, err)
			continue
		}
		read = true
		for name, u := range found {
			if _, ok := users[name]; !ok {
				users[name] = u
			}
		}
	}
	if !read {
		return nil
	}
	return users
}

// readSet reads one delegated key set, returning the records in it whose
// attestations are accepted by the trust anchors pinned in keyDir.
func readSet(cfg upspin.Config, keyDir string, set upspin.PathName) (map[upspin.UserName]*upspin.User, error) {
	const op errors.Op = "key/trust.readSet"
	if keyDir == "" {
		return nil, errors.E(op, errors.Invalid,
			"a delegated key set needs a "+ConfigKey+" holding the trust anchors that vouch for it")
	}
	p, err := upath.Parse(set)
	if err != nil {
		return nil, errors.E(op, err)
	}
	dir, err := bind.DirServerFor(cfg, p.User())
	if err != nil {
		return nil, errors.E(op, set, err)
	}
	entries, err := dir.Glob(string(set) + "/*")
	if err != nil {
		return nil, errors.E(op, set, err)
	}
	users := make(map[upspin.UserName]*upspin.User)
	for _, entry := range entries {
		if entry.IsDir() || entry.IsLink() {
			continue
		}
		// Records are named for the users they describe, so anything
		// else in the directory, such as an Access file, is not one.
		name, err := user.Clean(upspin.UserName(path.Base(string(entry.Name))))
		if err != nil {
			continue
		}
		if entry.IsIncomplete() {
			// The owner has not granted read access to the file,
			// so its contents cannot be fetched. Say so plainly:
			// it is the likeliest thing to be wrong with a set.
			log.Error.Printf("%s: %s: no read access; the owner must grant it explicitly", op, entry.Name)
			continue
		}
		data, err := clientutil.ReadAll(cfg, entry)
		if err != nil {
			log.Error.Printf("%s: %s: %v", op, entry.Name, err)
			continue
		}
		u, err := Accept(keyDir, data)
		if err != nil {
			log.Error.Printf("%s: %s: %v", op, entry.Name, err)
			continue
		}
		if u.Name != name {
			log.Error.Printf("%s: %s: holds a record for %s", op, entry.Name, u.Name)
			continue
		}
		users[name] = u
	}
	return users, nil
}

// A Checker looks up records in the sources other than the pinned key
// directory, so that a pinned record can be compared with what its owner
// publishes now. Nothing pushes a key change in Upspin, so a pin can quietly
// outlive the key it names; a check is how that is found deliberately rather
// than by the loss of access it eventually causes.
type Checker struct {
	cfg       upspin.Config
	dir       string
	sets      *sets
	discovery *discovery
}

// NewChecker returns a Checker for the sources the configuration names.
func NewChecker(cfg upspin.Config) (*Checker, error) {
	const op errors.Op = "key/trust.NewChecker"
	dir, err := Dir(cfg)
	if err != nil {
		return nil, errors.E(op, err)
	}
	paths, err := Sets(cfg)
	if err != nil {
		return nil, errors.E(op, err)
	}
	c := &Checker{cfg: cfg, dir: dir}
	if len(paths) > 0 {
		c.sets = &sets{paths: paths}
	}
	if Discovery(cfg) {
		c.discovery = &discovery{}
	}
	return c, nil
}

// Sources reports whether any source other than the pinned key directory is
// configured. With none there is nothing to check a pin against.
func (c *Checker) Sources() bool {
	return c.sets != nil || c.discovery != nil
}

// Published returns the record published for name by a delegated key set or by
// the user's own domain, or nil if none is. The pinned key directory is not
// consulted: the point of a check is to see what the other sources say.
func (c *Checker) Published(name upspin.UserName) *upspin.User {
	if c.sets != nil {
		if u := c.sets.lookup(c.cfg, c.dir, name); u != nil {
			return u
		}
	}
	if c.discovery != nil {
		if u := c.discovery.lookup(c.cfg, c.dir, name); u != nil {
			return u
		}
	}
	return nil
}
