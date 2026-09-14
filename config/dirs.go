// Copyright 2026 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"upspin.io/errors"
)

// Dirs returns the directories in which a configuration file is looked for,
// in order:
//
//  1. the user's configuration directory for Upspin: $XDG_CONFIG_HOME/upspin
//     on Unix, which is $HOME/.config/upspin unless the variable is set, and
//     the platform's equivalent elsewhere (see os.UserConfigDir);
//  2. $HOME/upspin, where earlier versions kept it;
//  3. the system configuration directories named by $XDG_CONFIG_DIRS, each
//     with upspin appended: /etc/xdg/upspin by default on Unix, none on
//     other systems.
//
// A directory that cannot be determined is left out; the list may be empty.
func Dirs() []string {
	var dirs []string
	if d, err := os.UserConfigDir(); err == nil && d != "" {
		dirs = append(dirs, filepath.Join(d, "upspin"))
	}
	if home, err := Homedir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "upspin"))
	}
	system := os.Getenv("XDG_CONFIG_DIRS")
	if system == "" {
		switch runtime.GOOS {
		case "windows", "darwin", "plan9", "ios", "android":
			// No convention for system-wide configuration directories.
		default:
			system = "/etc/xdg"
		}
	}
	for _, d := range filepath.SplitList(system) {
		if d = strings.TrimSpace(d); d != "" && filepath.IsAbs(d) {
			dirs = append(dirs, filepath.Join(d, "upspin"))
		}
	}
	return dirs
}

// Find returns the path of the named configuration file: name itself if it
// is absolute, or if it names a file in the current directory, and else the
// first of Dirs in which it exists. If it exists nowhere the error is
// NotExist and names the places that were looked in.
func Find(name string) (string, error) {
	return find(name, true)
}

// find is Find, looking in the current directory only when cwd is set. A
// bare name in the current directory must be a file: a directory called
// config, such as this package's own source, is not a configuration.
func find(name string, cwd bool) (string, error) {
	const op errors.Op = "config.Find"
	if filepath.IsAbs(name) {
		if _, err := os.Stat(name); err != nil {
			return "", errors.E(op, errors.NotExist, err)
		}
		return name, nil
	}
	if cwd {
		if info, err := os.Stat(name); err == nil && !info.IsDir() {
			return name, nil
		}
	}
	dirs := Dirs()
	for _, dir := range dirs {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.E(op, errors.NotExist, errors.Errorf("%s: not found in %s", name, strings.Join(dirs, ", ")))
}

// DefaultFile returns where the named configuration file is by default:
// in the first of Dirs that holds it, or, if none does, its place in the
// first of them, which is where a new one belongs. The current directory
// is not consulted: a default must not depend on where a command is run.
// With no directory to be found at all, the name is returned as it is.
func DefaultFile(name string) string {
	if p, err := find(name, false); err == nil {
		return p
	}
	if filepath.IsAbs(name) {
		return name
	}
	if dirs := Dirs(); len(dirs) > 0 {
		return filepath.Join(dirs[0], name)
	}
	return name
}
