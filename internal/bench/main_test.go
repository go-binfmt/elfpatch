package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func script(t *testing.T, dir, name, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stand-in tools are shell scripts")
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func oneFixture(dir string) ([]fixture, error) {
	p := filepath.Join(dir, "fix")
	return []fixture{{name: "stand-in", path: p}, {name: "stand-in grow", path: p, grow: true}}, os.WriteFile(p, []byte("not really an ELF"), 0o644)
}

func TestRunTable(t *testing.T) {
	d := t.TempDir()
	good := script(t, d, "good", `echo "tool 1.0"`)
	var out bytes.Buffer
	if err := run([]string{"-patchelf", good, "-elfpatch", good, "-rounds", "3"}, &out, oneFixture); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	// reference line, blank, header, rule, then one row per operation: four
	// for a fixture linked with room, three growth ones for the other
	if len(lines) != 4+4+3 || !strings.HasPrefix(lines[0], "reference: tool 1.0; rounds: 3") {
		t.Fatalf("%d lines:\n%s", len(lines), out.String())
	}
	for _, l := range lines[4:] {
		if !strings.HasPrefix(l, "| stand-in | `--") && !strings.HasPrefix(l, "| stand-in grow | `--") || !strings.HasSuffix(l, "x |") {
			t.Fatalf("bad row %q", l)
		}
	}
}

func TestRunFailures(t *testing.T) {
	d := t.TempDir()
	good := script(t, d, "good", "exit 0")
	bad := script(t, d, "bad", "echo nope; exit 3")
	for _, tc := range []struct {
		name string
		args []string
		mk   func(string) ([]fixture, error)
		want string
	}{
		{"tool fails", []string{"-patchelf", bad, "-elfpatch", good}, oneFixture, "--print-rpath"},
		{"elfpatch fails", []string{"-patchelf", good, "-elfpatch", bad}, oneFixture, "nope"},
		{"fixtures fail", []string{"-patchelf", good, "-elfpatch", good}, func(string) ([]fixture, error) { return nil, errors.New("no gcc") }, "no gcc"},
		{"bad flag", []string{"-nope"}, oneFixture, "flag provided but not defined"},
		{"zero rounds", []string{"-rounds", "0"}, oneFixture, "at least 1"},
		{"fixture vanished", []string{"-patchelf", good, "-elfpatch", good, "-rounds", "1"},
			func(dir string) ([]fixture, error) {
				return []fixture{{name: "gone", path: filepath.Join(dir, "missing")}}, nil
			}, "missing"},
	} {
		err := run(tc.args, &bytes.Buffer{}, tc.mk)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestTimeOneCopiesOutsideTheClock(t *testing.T) {
	d := t.TempDir()
	tool := script(t, d, "tool", "exit 0")
	src := filepath.Join(d, "src")
	os.WriteFile(src, []byte("x"), 0o644)
	if _, err := timeOne(d, tool, op{"edit", []string{"--x"}, true}, src); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(d, "work")); string(got) != "x" {
		t.Fatalf("the edit ran on %q, not on a fresh copy", got)
	}
	// a read-only op runs on the file itself
	if _, err := timeOne(d, tool, op{"print", nil, false}, src); err != nil {
		t.Fatal(err)
	}
	if _, err := timeOne(filepath.Join(d, "nodir"), tool, op{"edit", nil, true}, src); err == nil {
		t.Fatal("copy into a missing directory succeeded")
	}
}

func TestMedian(t *testing.T) {
	if got := median([]time.Duration{5, 1, 3}); got != 3 {
		t.Fatal(got)
	}
	if got := median([]time.Duration{4, 1, 3, 2}); got != 3 {
		t.Fatal(got) // upper median of an even count
	}
}

func TestFixturesNeedGccAndLinuxLinker(t *testing.T) {
	// Where gcc is missing (or the linker rejects GNU flags) fixtures must
	// say so instead of returning nothing.
	t.Setenv("PATH", t.TempDir())
	if _, err := fixtures(t.TempDir()); err == nil || !strings.Contains(err.Error(), "gcc") {
		t.Fatal(err)
	}
}

func TestRunWithoutAScratchDirectory(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "does", "not", "exist"))
	// A fixture builder that must never be reached: with no scratch directory
	// there is nothing to build in, and a "" directory would mean the cwd.
	err := run(nil, &bytes.Buffer{}, func(string) ([]fixture, error) {
		t.Fatal("fixtures built without a scratch directory")
		return nil, nil
	})
	if err == nil || !strings.Contains(err.Error(), "does") {
		t.Fatal(err)
	}
}
