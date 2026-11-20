package elfpatch_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The growth half of the differential lane: edits that do NOT fit in place, on
// gcc-built executables (PIE and not) and shared libraries, applied with
// patchelf and with elfpatch. Compared: the semantic fields readelf -d -l -V
// reports (NEEDED, SONAME, RPATH, RUNPATH, the program interpreter, the
// version-needed file names, the kinds of program header), every --print-*
// output, and that readelf has no complaint about the result. Then the edited
// program is RUN: it must still start and find its libraries with no
// LD_LIBRARY_PATH, which is the only test that the loader accepts the new
// layout. For libraries, a program is linked against the edited library and
// run.
//
// ELFPATCH_PATCHELF names another patchelf (the lane's reference is whatever is
// first on PATH), and ELFPATCH_LAYOUT_STRICT=1 additionally requires the same
// PT_LOAD flags, the same file size and the same program and section header
// tables as the reference, which holds against the release this engine was
// ported from (0.19.3).

func TestDifferentialGrowth(t *testing.T) {
	tools := need(t, "gcc", "readelf", "patchelf")
	ref := tools["patchelf"]
	if p := os.Getenv("ELFPATCH_PATCHELF"); p != "" {
		ref = p
	}
	dir := t.TempDir()
	ver, _ := try("", ref, "--version")
	t.Logf("reference: %s (%s)", strings.TrimSpace(ver), ref)

	cli := os.Getenv("ELFPATCH_BIN")
	if cli == "" {
		cli = filepath.Join(dir, "elfpatch")
		sh(t, ".", "go", "build", "-o", cli, "./cmd/elfpatch")
	}

	write := func(name, body string) { os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644) }
	write("foo.c", libC)
	write("main.c", mainC)
	write("bar.c", "int foo(int);\nint bar(int x) { return foo(x) + 1; }\n")
	lib := filepath.Join(dir, "lib")
	os.Mkdir(lib, 0o755)
	sh(t, dir, "gcc", "-shared", "-fPIC", "-Wl,-soname,libfoo.so.1", "-o", filepath.Join(lib, "libfoo.so.1"), "foo.c")
	// copies under other names: the loader finds a library by the DT_NEEDED
	// name, and a version-needed file name is matched against that name too
	longFoo := "libfoo-with-a-very-long-replacement-name-" + strings.Repeat("x", 60) + ".so.1"
	for _, n := range []string{longFoo, "libfoo2.so.1"} {
		data, _ := os.ReadFile(filepath.Join(lib, "libfoo.so.1"))
		os.WriteFile(filepath.Join(lib, n), data, 0o755)
	}
	libm := strings.TrimSpace(sh(t, dir, "gcc", "-print-file-name=libm.so.6"))
	longM := "libm-copy-with-a-very-long-replacement-name-" + strings.Repeat("m", 60) + ".so.6"
	haveM := false
	if data, err := os.ReadFile(libm); err == nil {
		os.WriteFile(filepath.Join(lib, longM), data, 0o755)
		haveM = true
	}
	sh(t, dir, "gcc", "-shared", "-fPIC", "-o", filepath.Join(lib, "libbar.so"), "bar.c", "-L"+lib, "-l:libfoo.so.1")
	sh(t, dir, "gcc", "-shared", "-fPIC", "-Wl,-soname,libbaz.so.1", "-o", filepath.Join(dir, "libbaz.so.1"), "foo.c")

	short := "/x"
	build := func(out string, extra ...string) string {
		p := filepath.Join(dir, out)
		args := append([]string{"-o", p, "main.c", "-L" + lib, "-l:libfoo.so.1", "-lm"}, extra...)
		sh(t, dir, "gcc", args...)
		return p
	}
	progs := map[string]string{
		"pie":          build("prog-pie", "-Wl,-rpath,"+short),
		"nopie":        build("prog-nopie", "-no-pie", "-Wl,-rpath,"+short),
		"pie-norpath":  build("prog-pie-norpath"),
		"nopie-norpat": build("prog-nopie-norpath", "-no-pie"),
	}
	libs := map[string]string{
		"lib":          filepath.Join(lib, "libfoo.so.1"),
		"lib-nosoname": filepath.Join(dir, "libnosoname.so"),
	}
	sh(t, dir, "gcc", "-shared", "-fPIC", "-o", libs["lib-nosoname"], "foo.c")

	// a long interpreter that exists: a copy of the real loader
	interp := strings.TrimSpace(sh(t, "", ref, "--print-interpreter", progs["pie"]))
	longDir := filepath.Join(dir, "an-interpreter-directory-with-a-rather-long-name-"+strings.Repeat("d", 80))
	os.MkdirAll(longDir, 0o755)
	longInterp := filepath.Join(longDir, filepath.Base(interp))
	if data, err := os.ReadFile(interp); err == nil {
		os.WriteFile(longInterp, data, 0o755)
	} else {
		t.Fatalf("cannot read the loader %s: %v", interp, err)
	}
	longRpath := "$ORIGIN/lib:" + strings.Repeat("/nonexistent/directory/with/a/long/name", 8)
	hugeRpath := "$ORIGIN/lib:" + strings.Repeat("/nonexistent/"+strings.Repeat("h", 200), 40) // over 8 KiB

	type pcase struct {
		name    string
		fixture string
		args    []string
		useLib  bool // the program needs lib/ to run; the edit must supply it
		skip    bool
	}
	pcases := []pcase{}
	for _, fx := range []string{"pie", "nopie"} {
		pcases = append(pcases,
			pcase{"set-interpreter long", fx, []string{"--set-interpreter", longInterp, "--set-rpath", "$ORIGIN/lib"}, false, false},
			pcase{"set-rpath long", fx, []string{"--set-rpath", longRpath}, false, false},
			pcase{"set-rpath huge (over 8 KiB)", fx, []string{"--set-rpath", hugeRpath}, false, false},
			pcase{"force-rpath long", fx, []string{"--force-rpath", "--set-rpath", longRpath}, false, false},
			pcase{"add-rpath to short", fx, []string{"--add-rpath", "$ORIGIN/lib"}, false, false},
			pcase{"add-needed", fx, []string{"--add-needed", "libfoo2.so.1", "--set-rpath", "$ORIGIN/lib"}, false, false},
			pcase{"add-needed two", fx, []string{"--add-needed", "libfoo2.so.1", "--add-needed", "libbaz.so.1", "--set-rpath", "$ORIGIN/lib:$ORIGIN"}, false, false},
			pcase{"replace-needed long", fx, []string{"--replace-needed", "libfoo.so.1", longFoo, "--set-rpath", "$ORIGIN/lib"}, false, false},
			pcase{"replace-needed libm (version needs)", fx, []string{"--replace-needed", "libm.so.6", longM, "--set-rpath", "$ORIGIN/lib"}, false, !haveM},
			pcase{"combined", fx, []string{"--set-interpreter", longInterp, "--set-rpath", longRpath, "--replace-needed", "libfoo.so.1", longFoo, "--add-needed", "libfoo2.so.1", "--remove-needed", "libm.so.6"}, false, false},
			pcase{"page-size 64k", fx, []string{"--page-size", "65536", "--set-rpath", longRpath}, false, false},
		)
	}
	for _, fx := range []string{"pie-norpath", "nopie-norpat"} {
		pcases = append(pcases,
			pcase{"set-rpath where there is none", fx, []string{"--set-rpath", "$ORIGIN/lib"}, false, false},
			pcase{"add-rpath where there is none", fx, []string{"--add-rpath", "$ORIGIN/lib"}, false, false},
			pcase{"force-rpath where there is none", fx, []string{"--force-rpath", "--set-rpath", "$ORIGIN/lib"}, false, false},
			pcase{"set-soname on a program (patchelf ignores it)", fx, []string{"--set-soname", "libwhat.so", "--set-rpath", "$ORIGIN/lib"}, false, false},
		)
	}

	semantic := func(t *testing.T, file string) []string { return dynamic(t, tools["readelf"], file) }
	clean := func(t *testing.T, file string) {
		t.Helper()
		out, err := try(dir, tools["readelf"], "-W", "-a", file)
		if err != nil || strings.Contains(out, "Warning") || strings.Contains(out, "Error:") {
			t.Fatalf("readelf complains about %s: %v\n%s", filepath.Base(file), err, firstLines(out, 12))
		}
	}
	same := func(t *testing.T, name string, want, have []string) {
		t.Helper()
		if !slices.Equal(want, have) {
			t.Fatalf("%s: readelf differs\npatchelf: %q\nelfpatch: %q", name, want, have)
		}
	}
	prints := func(t *testing.T, a, b string) {
		t.Helper()
		for _, p := range []string{"--print-rpath", "--print-needed", "--print-interpreter", "--print-soname"} {
			w, werr := try(dir, ref, p, a)
			h, herr := try(dir, cli, p, b)
			if (werr == nil) != (herr == nil) || (werr == nil && w != h) {
				t.Fatalf("%s differs: patchelf %q (%v) elfpatch %q (%v)", p, w, werr, h, herr)
			}
		}
	}
	strict := os.Getenv("ELFPATCH_LAYOUT_STRICT") != ""
	loadFlags := func(t *testing.T, file string) []string {
		var out []string
		for _, l := range strings.Split(sh(t, "", tools["readelf"], "-W", "-l", file), "\n") {
			if f := strings.Fields(l); len(f) > 7 && f[0] == "LOAD" {
				out = append(out, strings.Join(f[6:len(f)-1], ""))
			}
		}
		slices.Sort(out)
		return out
	}

	layoutSame := func(t *testing.T, a, b string) {
		t.Helper()
		if !strict {
			return
		}
		sa, _ := os.Stat(a)
		sb, _ := os.Stat(b)
		if w, h := loadFlags(t, a), loadFlags(t, b); !slices.Equal(w, h) {
			t.Fatalf("PT_LOAD flags differ: patchelf %q elfpatch %q", w, h)
		}
		if sa.Size() != sb.Size() {
			t.Fatalf("file size differs: patchelf %d, elfpatch %d", sa.Size(), sb.Size())
		}
		// the whole layout: every program header and section header
		w := sh(t, "", tools["readelf"], "-W", "-l", "-S", a)
		h := sh(t, "", tools["readelf"], "-W", "-l", "-S", b)
		if strings.ReplaceAll(w, a, "FILE") != strings.ReplaceAll(h, b, "FILE") {
			t.Fatalf("program/section headers differ\npatchelf:\n%s\nelfpatch:\n%s", w, h)
		}
	}
	for _, c := range pcases {
		t.Run(c.fixture+"/"+c.name, func(t *testing.T) {
			if c.skip {
				t.Skip("no libm.so.6 to copy here")
			}
			a, b := filepath.Join(dir, "ref-"+c.fixture), filepath.Join(dir, "got-"+c.fixture)
			for _, p := range []string{a, b} {
				data, _ := os.ReadFile(progs[c.fixture])
				os.WriteFile(p, data, 0o755)
			}
			if out, err := try(dir, ref, append(slices.Clone(c.args), a)...); err != nil {
				t.Fatalf("patchelf refused: %v\n%s", err, out)
			}
			if out, err := try(dir, cli, append(slices.Clone(c.args), b)...); err != nil {
				t.Fatalf("elfpatch refused: %v\n%s", err, out)
			}
			same(t, c.name, semantic(t, a), semantic(t, b))
			prints(t, a, b)
			clean(t, b)
			sa, _ := os.Stat(a)
			sb, _ := os.Stat(b)
			t.Logf("file size: patchelf %d, elfpatch %d (input %d)", sa.Size(), sb.Size(), statSize(progs[c.fixture]))
			layoutSame(t, a, b)
			run := exec.Command(b)
			run.Dir = t.TempDir() // nothing relative to the working directory helps it
			if out, err := run.CombinedOutput(); err != nil {
				t.Fatalf("the edited program does not run: %v\n%s", err, out)
			}
		})
	}

	// Libraries: edit the library, then link a program against the edited
	// library under its (possibly new) soname and run that.
	type lcase struct {
		name, fixture string
		args          []string
	}
	longSoname := "libfoo-with-a-very-long-soname-" + strings.Repeat("s", 70) + ".so.7"
	lcases := []lcase{
		{"set-soname long", "lib", []string{"--set-soname", longSoname}},
		{"set-soname where there is none", "lib-nosoname", []string{"--set-soname", "libnosoname.so.3"}},
		{"set-rpath where there is none", "lib-nosoname", []string{"--set-rpath", "$ORIGIN/lib"}},
		{"add-rpath", "lib", []string{"--add-rpath", "$ORIGIN/some/where/with/a/long/name/" + strings.Repeat("r", 100)}},
		{"add-needed", "lib", []string{"--add-needed", "libm.so.6"}},
		{"set-rpath long and add-needed", "lib", []string{"--set-rpath", longRpath, "--add-needed", "libm.so.6"}},
		{"set-soname and set-rpath", "lib", []string{"--set-soname", longSoname, "--set-rpath", longRpath}},
	}
	for _, c := range lcases {
		t.Run(c.fixture+"/"+c.name, func(t *testing.T) {
			a, b := filepath.Join(dir, "ref-"+c.fixture+".so"), filepath.Join(dir, "got-"+c.fixture+".so")
			for _, p := range []string{a, b} {
				data, _ := os.ReadFile(libs[c.fixture])
				os.WriteFile(p, data, 0o755)
			}
			if out, err := try(dir, ref, append(slices.Clone(c.args), a)...); err != nil {
				t.Fatalf("patchelf refused: %v\n%s", err, out)
			}
			if out, err := try(dir, cli, append(slices.Clone(c.args), b)...); err != nil {
				t.Fatalf("elfpatch refused: %v\n%s", err, out)
			}
			same(t, c.name, semantic(t, a), semantic(t, b))
			prints(t, a, b)
			clean(t, b)
			layoutSame(t, a, b)
			// link a program against the edited library and run it
			name := "libfoo.so.1"
			if s := strings.TrimSpace(sh(t, "", cli, "--print-soname", b)); s != "" {
				name = s
			} else {
				name = "libnosoname.so"
			}
			ldir := t.TempDir()
			data, _ := os.ReadFile(b)
			os.WriteFile(filepath.Join(ldir, name), data, 0o755)
			prog := filepath.Join(ldir, "prog")
			sh(t, dir, "gcc", "-o", prog, "main.c", "-L"+ldir, "-l:"+name, "-lm", "-Wl,-rpath,"+ldir)
			run := exec.Command(prog)
			run.Dir = ldir
			// the edited library may now depend on lib/ (rpath), supplied by the edit
			if out, err := run.CombinedOutput(); err != nil {
				t.Fatalf("a program using the edited library does not run: %v\n%s", err, out)
			}
		})
	}

	t.Run("a refusal writes nothing", func(t *testing.T) {
		got := filepath.Join(dir, "refuse")
		data, _ := os.ReadFile(progs["pie"])
		os.WriteFile(got, data, 0o755)
		// a stripped-of-sections file cannot be grown: truncate the section
		// header table off the end by zeroing e_shnum would corrupt it, so use
		// a text file instead: not an ELF
		txt := filepath.Join(dir, "not-elf")
		os.WriteFile(txt, []byte("not an elf file at all"), 0o644)
		if out, err := try(dir, cli, "--set-rpath", longRpath, txt); err == nil {
			t.Fatalf("a text file was accepted: %s", out)
		}
		after, _ := os.ReadFile(txt)
		if string(after) != "not an elf file at all" {
			t.Fatal("a refusal wrote")
		}
	})
}

func statSize(p string) int64 {
	st, err := os.Stat(p)
	if err != nil {
		return -1
	}
	return st.Size()
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
