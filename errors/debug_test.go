// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build debug

package errors_test

import (
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"upspin.io/errors"
	"upspin.io/upspin"
	"upspin.io/valid"
)

// repoDir is the directory holding this repository, taken from the path of
// this file as the compiler recorded it. The frames in an error stack are
// recorded the same way, so deriving the directory is better than assuming the
// repository sits in one named upspin.io: that holds under GOPATH, but a
// module may be cloned into a directory of any name. It is also right under
// -trimpath, which shortens both this path and those in the stack alike.
var repoDir = func() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("errors: cannot determine the path of debug_test.go")
	}
	return filepath.Dir(filepath.Dir(file))
}()

var errorLines = strings.Split(strings.TrimSpace(fmt.Sprintf(`
	%[1]s/errors/debug_test.go:\d+: upspin.io/errors_test..*
	%[1]s/errors/debug_test.go:\d+: .*
	%[1]s/valid/valid.go:\d+: .*valid.UserName:
	%[1]s/user/user.go:\d+: ...user.Parse: op: user@home/path: invalid operation:
	valid.UserName:
	user.Parse: user bad-username: user name must contain one @ symbol
`, regexp.QuoteMeta(repoDir))), "\n")

var errorLineREs = make([]*regexp.Regexp, len(errorLines))

func init() {
	for i, s := range errorLines {
		errorLineREs[i] = regexp.MustCompile(fmt.Sprintf("^%s$", s))
	}
}

// Test that the error stack includes all the function calls between where it
// was generated and where it was printed. It should not include the name
// of the function in which the Error method is called. It should coalesce
// the call stacks of nested errors into one single stack, and present that
// stack before the other error values.
func TestDebug(t *testing.T) {
	got := printErr(t, func1())
	lines := strings.Split(got, "\n")
	for i, re := range errorLineREs {
		if i >= len(lines) {
			// Handled by line number check.
			break
		}
		if !re.MatchString(lines[i]) {
			t.Errorf("error does not match at line %v, got:\n\t%q\nwant:\n\t%q", i, lines[i], re)
		}
	}
	// Check number of lines after checking the lines themselves,
	// as the content check will likely be more illuminating.
	if got, want := len(lines), len(errorLines); got != want {
		t.Errorf("got %v lines of errors, want %v", got, want)
	}
}

func printErr(t *testing.T, err error) string {
	return err.Error()
}

func func1() error {
	var t T
	return t.func2()
}

type T struct{}

func (T) func2() error {
	return errors.E(errors.Op("op"), upspin.PathName("user@home/path"), func3())
}

func func3() error {
	return func4()
}

func func4() error {
	return valid.UserName("bad-username")
}
