package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/go-binfmt/elfpatch/internal/elfgen"
)

func fixture(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "prog")
	img := elfgen.Build(elfgen.Spec{
		Interp: "/lib64/ld-linux-x86-64.so.2", InterpSlot: 40,
		Needed: []string{"libfoo.so.1", "libm.so.6"}, Soname: "libp.so",
		Rpath: "/opt/placeholder/aaaaaaaaaaaaaaaaaaaa", Symbols: []string{"main"},
	})
	if err := os.WriteFile(p, img, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func do(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := RootCmd()
	var o, e bytes.Buffer
	cmd.SetOut(&o)
	cmd.SetErr(&e)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return o.String(), e.String(), err
}

func TestPrints(t *testing.T) {
	p := fixture(t)
	for _, tc := range []struct{ flag, want string }{
		{"--print-interpreter", "/lib64/ld-linux-x86-64.so.2\n"},
		{"--print-rpath", "/opt/placeholder/aaaaaaaaaaaaaaaaaaaa\n"},
		{"--print-needed", "libfoo.so.1\nlibm.so.6\n"},
		{"--print-soname", "libp.so\n"},
	} {
		out, _, err := do(t, tc.flag, p)
		if err != nil || out != tc.want {
			t.Fatalf("%s: %q %v", tc.flag, out, err)
		}
	}
	// file before flag works too
	if out, _, err := do(t, p, "--print-soname"); err != nil || out != "libp.so\n" {
		t.Fatal(out, err)
	}
}

func TestEdits(t *testing.T) {
	p := fixture(t)
	if _, _, err := do(t, "--set-rpath", "$ORIGIN/lib", "--set-interpreter", "/ld.so", "--remove-needed", "libm.so.6", p); err != nil {
		t.Fatal(err)
	}
	out, _, _ := do(t, "--print-rpath", "--print-interpreter", "--print-needed", p)
	if out != "/ld.so\n$ORIGIN/lib\nlibfoo.so.1\n" {
		t.Fatalf("%q", out)
	}
	if _, _, err := do(t, "--replace-needed", "libfoo.so.1", "libbar.so.1", p); err != nil {
		t.Fatal(err)
	}
	if out, _, _ := do(t, "--print-needed", p); out != "libbar.so.1\n" {
		t.Fatalf("%q", out)
	}
	if _, _, err := do(t, "--remove-rpath", p); err != nil {
		t.Fatal(err)
	}
	if out, _, _ := do(t, "--print-rpath", p); out != "\n" {
		t.Fatalf("%q", out)
	}
}

func TestForceAndShrink(t *testing.T) {
	p := fixture(t)
	if _, _, err := do(t, "--force-rpath", "--set-rpath", "/x:/nonexistent", p); err != nil {
		t.Fatal(err)
	}
	if _, _, err := do(t, "--shrink-rpath", p); err != nil {
		t.Fatal(err)
	}
	if out, _, _ := do(t, "--print-rpath", p); out != "\n" {
		t.Fatalf("%q", out)
	}
}

func TestDryRun(t *testing.T) {
	p := fixture(t)
	before, _ := os.ReadFile(p)
	out, _, err := do(t, "--dry-run", "--set-rpath", "/new", p)
	if err != nil || !strings.Contains(out, `runpath: "/opt/placeholder/aaaaaaaaaaaaaaaaaaaa" -> "/new"`) {
		t.Fatal(out, err)
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("dry run wrote")
	}
}

func TestOutput(t *testing.T) {
	p := fixture(t)
	o := p + ".out"
	if _, _, err := do(t, "--set-rpath", "/o", "--output", o, p); err != nil {
		t.Fatal(err)
	}
	if out, _, _ := do(t, "--print-rpath", o); out != "/o\n" {
		t.Fatal(out)
	}
	if out, _, _ := do(t, "--print-rpath", p); out == "/o\n" {
		t.Fatal("input modified")
	}
	if _, _, err := do(t, "--set-rpath", "/o", "--output", o, p, p); err == nil {
		t.Fatal("--output with two files accepted")
	}
}

func TestRefusals(t *testing.T) {
	p := fixture(t)
	before, _ := os.ReadFile(p)
	long := "/" + strings.Repeat("z", 200)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--set-rpath", long, p}, "phase 2"},
		{[]string{"--set-interpreter", long, p}, "phase 2"},
		{[]string{"--add-needed", "libx.so", p}, "phase 2"},
		{[]string{"--set-soname", "x", p}, "phase 2"},
		{[]string{"--replace-needed", "libm.so.6", "libmuchlonger.so.6", p}, "phase 2"},
		{[]string{"--replace-needed", "a"}, "two arguments"},
		{[]string{"--bogus", p}, "unknown flag"},
		{[]string{"--set-rpath", "/x"}, "no FILE"},
		{[]string{p}, "nothing to do"},
		{[]string{"--print-needed", filepath.Join(t.TempDir(), "missing")}, "no such file"},
	} {
		_, _, err := do(t, tc.args...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%v: %v, want %q", tc.args, err, tc.want)
		}
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("a refusal wrote")
	}
	// prints on a file lacking the field
	bare := filepath.Join(t.TempDir(), "bare")
	os.WriteFile(bare, elfgen.Build(elfgen.Spec{}), 0o755)
	for _, f := range []string{"--print-interpreter", "--print-soname"} {
		if _, _, err := do(t, f, bare); err == nil {
			t.Fatal(f, "succeeded on a file without it")
		}
	}
	if _, _, err := do(t, "--set-rpath", "/x", bare); err == nil || !strings.Contains(err.Error(), "phase 2") {
		t.Fatal(err)
	}
	// not an ELF
	txt := filepath.Join(t.TempDir(), "t")
	os.WriteFile(txt, []byte("not elf at all, sorry"), 0o644)
	if _, _, err := do(t, "--print-rpath", txt); err == nil {
		t.Fatal("text accepted")
	}
}

func TestVersionAndHelp(t *testing.T) {
	out, _, err := do(t, "--version")
	if err != nil || out != "elfpatch dev\n" {
		t.Fatal(out, err)
	}
	out, _, err = do(t, "--help")
	if err != nil || !strings.Contains(out, "--set-rpath") || strings.Contains(out, "--add-needed") {
		t.Fatal(out, err)
	}
}

func TestVersionOverride(t *testing.T) {
	defer func(f func() (*debug.BuildInfo, bool)) { readBuildInfo = f; Version = "dev" }(readBuildInfo)
	stamped := func(v string) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) { return &debug.BuildInfo{Main: debug.Module{Version: v}}, true }
	}
	for _, tc := range []struct{ ldflag, stamp, want string }{
		{"v9.9.9", "v1.2.3", "v9.9.9"}, // -ldflags wins over the stamp
		{"dev", "v1.2.3", "v1.2.3"},    // else the module version Go stamped
		{"dev", "(devel)", "dev"},      // an unstamped build
		{"dev", "", "dev"},             // no version at all
	} {
		Version, readBuildInfo = tc.ldflag, stamped(tc.stamp)
		if out, _, _ := do(t, "--version"); out != "elfpatch "+tc.want+"\n" {
			t.Fatalf("%+v: %q", tc, out)
		}
	}
	Version, readBuildInfo = "dev", func() (*debug.BuildInfo, bool) { return nil, false }
	if out, _, _ := do(t, "--version"); out != "elfpatch dev\n" {
		t.Fatal(out)
	}
}

func TestMainExit(t *testing.T) {
	var code int
	osExit = func(c int) { code = c }
	defer func() { osExit = os.Exit }()
	old := os.Args
	defer func() { os.Args = old }()
	os.Args = []string{"elfpatch", "--bogus"}
	main()
	if code != 1 {
		t.Fatal("exit", code)
	}
	code = 0
	os.Args = []string{"elfpatch", "--version"}
	main()
	if code != 0 {
		t.Fatal("exit", code)
	}
}
