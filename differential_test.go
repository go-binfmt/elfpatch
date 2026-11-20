package elfpatch_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// The differential lane: build real ELF files with gcc, apply the same edit
// with NixOS patchelf and with elfpatch, and compare what readelf reports
// (the dynamic tags NEEDED/SONAME/RPATH/RUNPATH, and the program interpreter)
// plus every --print-* output byte for byte. It needs Linux, gcc, readelf and
// patchelf, so it SKIPS elsewhere (a macOS laptop has none of them) and runs
// in CI on ubuntu and, for development, in a Linux container. The compiled
// fixtures are built from the tiny C files below at test time: nothing binary
// is committed and no third-party licence is involved.

const libC = "int foo(int x) { return x + 41; }\n"
const mainC = "#include <math.h>\nint foo(int);\nint main(void) { return foo(1) == 42 && sqrt(4.0) == 2.0 ? 0 : 1; }\n"

func need(t *testing.T, tools ...string) map[string]string {
	t.Helper()
	// CI sets ELFPATCH_REQUIRE_DIFF so that a missing tool is a failure there,
	// and ELFPATCH_SKIP_DIFF=<reason> for the one lane (qemu) that cannot exec
	// host tools. Everywhere else a missing prerequisite is a stated skip.
	if why := os.Getenv("ELFPATCH_SKIP_DIFF"); why != "" {
		t.Skip("differential lane skipped: " + why)
	}
	missing := func(format string, a ...any) {
		t.Helper()
		if os.Getenv("ELFPATCH_REQUIRE_DIFF") != "" {
			t.Fatalf("differential lane is REQUIRED here but "+format, a...)
		}
		t.Skipf("differential lane needs "+format, a...)
	}
	if runtime.GOOS != "linux" {
		missing("Linux (gcc, readelf, patchelf), this is %s", runtime.GOOS)
	}
	paths := map[string]string{}
	for _, tool := range tools {
		p, err := exec.LookPath(tool)
		if err != nil {
			missing("%s on PATH", tool)
		}
		paths[tool] = p
	}
	return paths
}

func sh(t *testing.T, dir string, name string, args ...string) string {
	t.Helper()
	c := exec.Command(name, args...)
	c.Dir = dir
	var o, e bytes.Buffer
	c.Stdout, c.Stderr = &o, &e
	if err := c.Run(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, e.String())
	}
	return o.String()
}

func try(dir, name string, args ...string) (string, error) {
	c := exec.Command(name, args...)
	c.Dir = dir
	var o bytes.Buffer
	c.Stdout, c.Stderr = &o, &o
	err := c.Run()
	return o.String(), err
}

var tagLine = regexp.MustCompile(`\((NEEDED|SONAME|RPATH|RUNPATH)\)\s+(.*)$`)
var interpLine = regexp.MustCompile(`Requesting program interpreter: (.*)\]`)
var verneedLine = regexp.MustCompile(`Version: \d+\s+File: (\S+)\s+Cnt:`)

// segLine matches the program headers that are not PT_LOAD: how many of each
// kind there are is part of the file's meaning (a stack that is not executable,
// a RELRO); where the PT_LOADs sit is the layout, which may differ, and so may
// the number of PT_NOTEs (patchelf splits one that covers several notes the
// moment it relocates anything, and an edit in place relocates nothing).
var segLine = regexp.MustCompile(`^\s+(PHDR|INTERP|DYNAMIC|NOTE|TLS|GNU_\w+|[A-Z_]+)\s+0x`)

// dynamic reduces readelf output to the semantic lines.
func dynamic(t *testing.T, readelf, file string) []string {
	t.Helper()
	var out, segs []string
	for _, l := range strings.Split(sh(t, "", readelf, "-W", "-d", "-l", "-V", file), "\n") {
		if m := tagLine.FindStringSubmatch(l); m != nil {
			out = append(out, m[1]+" "+m[2])
		} else if m := interpLine.FindStringSubmatch(l); m != nil {
			out = append(out, "INTERP "+m[1])
		} else if m := verneedLine.FindStringSubmatch(l); m != nil {
			out = append(out, "VERNEED "+m[1])
		} else if m := segLine.FindStringSubmatch(l); m != nil && m[1] != "LOAD" && m[1] != "NOTE" {
			segs = append(segs, "SEG "+m[1])
		}
	}
	slices.Sort(segs)
	return append(out, segs...)
}

func TestDifferentialAgainstPatchelf(t *testing.T) {
	tools := need(t, "gcc", "readelf", "patchelf")
	dir := t.TempDir()
	ver, _ := try("", tools["patchelf"], "--version")
	t.Logf("reference: %s", strings.TrimSpace(ver))

	cli := os.Getenv("ELFPATCH_BIN")
	if cli == "" {
		cli = filepath.Join(dir, "elfpatch")
		sh(t, ".", "go", "build", "-o", cli, "./cmd/elfpatch")
	}

	os.WriteFile(filepath.Join(dir, "foo.c"), []byte(libC), 0o644)
	os.WriteFile(filepath.Join(dir, "main.c"), []byte(mainC), 0o644)
	lib := filepath.Join(dir, "lib")
	os.Mkdir(lib, 0o755)
	sh(t, dir, "gcc", "-shared", "-fPIC", "-Wl,-soname,libfoo.so.1", "-o", filepath.Join(lib, "libfoo.so.1"), "foo.c")
	placeholder := "/placeholder/" + strings.Repeat("p", 120)
	ph := func(extra string) string { return placeholder + extra }
	fixtures := map[string][]string{
		"runpath": {"-Wl,--enable-new-dtags", "-Wl,-rpath," + ph("")},
		"rpath":   {"-Wl,--disable-new-dtags", "-Wl,-rpath," + ph("")},
		"mixed":   {"-Wl,--enable-new-dtags", "-Wl,-rpath,/nonexistent/one:" + lib + ":/nonexistent/two:" + ph(":/usr/lib")},
	}
	bins := map[string]string{}
	for name, flags := range fixtures {
		out := filepath.Join(dir, "prog-"+name)
		args := append([]string{"-o", out, "main.c", "-L" + lib, "-l:libfoo.so.1", "-lm"}, flags...)
		sh(t, dir, "gcc", args...)
		bins[name] = out
	}

	interp := strings.TrimSpace(sh(t, "", tools["patchelf"], "--print-interpreter", bins["runpath"]))
	cases := []struct {
		name, fixture string
		args          []string
		runs          bool // the patched program must still run (needs libfoo found)
	}{
		{"set-rpath origin", "runpath", []string{"--set-rpath", "$ORIGIN/lib"}, true},
		{"set-rpath real dir", "runpath", []string{"--set-rpath", lib}, true},
		{"set-rpath converts RPATH", "rpath", []string{"--set-rpath", lib}, true},
		{"force-rpath", "runpath", []string{"--force-rpath", "--set-rpath", lib}, true},
		{"set-rpath empty", "runpath", []string{"--set-rpath", ""}, false},
		{"remove-rpath", "rpath", []string{"--remove-rpath"}, false},
		{"shrink-rpath", "mixed", []string{"--shrink-rpath"}, true},
		{"remove-needed libm", "runpath", []string{"--remove-needed", "libm.so.6"}, false},
		{"shrink-rpath to empty", "rpath", []string{"--shrink-rpath"}, false},
		{"remove-needed absent", "runpath", []string{"--remove-needed", "libnothere.so"}, true},
		{"replace-needed same length", "runpath", []string{"--replace-needed", "libm.so.6", "libm.so.6"}, true},
		{"replace-needed shorter", "runpath", []string{"--replace-needed", "libfoo.so.1", "libfoo.so"}, false},
		{"set-interpreter same", "runpath", []string{"--set-interpreter", interp}, true},
		{"combined", "runpath", []string{"--set-rpath", lib, "--remove-needed", "libm.so.6"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ref := filepath.Join(dir, "ref")
			got := filepath.Join(dir, "got")
			for _, p := range []string{ref, got} {
				data, _ := os.ReadFile(bins[c.fixture])
				os.WriteFile(p, data, 0o755)
			}
			if out, err := try(dir, tools["patchelf"], append(slices.Clone(c.args), ref)...); err != nil {
				t.Fatalf("patchelf refused: %v\n%s", err, out)
			}
			if out, err := try(dir, cli, append(slices.Clone(c.args), got)...); err != nil {
				t.Fatalf("elfpatch refused: %v\n%s", err, out)
			}
			want, have := dynamic(t, tools["readelf"], ref), dynamic(t, tools["readelf"], got)
			if !slices.Equal(want, have) {
				t.Fatalf("readelf differs\npatchelf: %q\nelfpatch: %q", want, have)
			}
			// in place: the file did not grow (patchelf may move things; we must not)
			a, _ := os.Stat(bins[c.fixture])
			b, _ := os.Stat(got)
			if a.Size() != b.Size() {
				t.Fatalf("size changed %d -> %d", a.Size(), b.Size())
			}
			if c.runs {
				// An edit that leaves the search path alone cannot find libfoo
				// by itself (the link-time path is a placeholder), so the loader
				// is told where it is; an edit that sets the path must find it
				// with no help.
				run := exec.Command(got)
				run.Dir = dir
				if !slices.ContainsFunc(c.args, func(a string) bool { return strings.Contains(a, "rpath") }) {
					run.Env = append(os.Environ(), "LD_LIBRARY_PATH="+lib)
				}
				if out, err := run.CombinedOutput(); err != nil {
					t.Fatalf("patched program does not run: %v\n%s", err, out)
				}
			}
			// every --print-* agrees, on the edited file
			for _, p := range []string{"--print-rpath", "--print-needed", "--print-interpreter"} {
				w, werr := try(dir, tools["patchelf"], p, ref)
				h, herr := try(dir, cli, p, got)
				if (werr == nil) != (herr == nil) || (werr == nil && w != h) {
					t.Fatalf("%s differs: patchelf %q (%v) elfpatch %q (%v)", p, w, werr, h, herr)
				}
			}
		})
	}

	t.Run("print on a shared library", func(t *testing.T) {
		so := filepath.Join(lib, "libfoo.so.1")
		for _, p := range []string{"--print-soname", "--print-needed", "--print-rpath"} {
			w, werr := try(dir, tools["patchelf"], p, so)
			h, herr := try(dir, cli, p, so)
			if (werr == nil) != (herr == nil) || (werr == nil && w != h) {
				t.Fatalf("%s: patchelf %q (%v) elfpatch %q (%v)", p, w, werr, h, herr)
			}
		}
	})
}
