package elfpatch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/go-binfmt/elfpatch/internal/elfgen"
)

type variant struct {
	name  string
	class int
	big   bool
}

var variants = []variant{
	{"64le", 64, false}, {"64be", 64, true}, {"32le", 32, false}, {"32be", 32, true},
}

func spec(v variant) elfgen.Spec {
	return elfgen.Spec{
		Class: v.class, BigEndian: v.big,
		Interp: "/lib64/ld-linux-x86-64.so.2", InterpSlot: 40,
		Needed: []string{"libfoo.so.1", "libm.so.6", "libc.so.6"},
		Soname: "libself.so.2",
		Rpath:  "/opt/placeholder/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RpathSlot: 60,
		Symbols: []string{"main", "printf"},
	}
}

func eachVariant(t *testing.T, fn func(t *testing.T, v variant)) {
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) { fn(t, v) })
	}
}

func mustParse(t *testing.T, b []byte) *File {
	t.Helper()
	f, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func write(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(p, b, 0o751); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPrint(t *testing.T) {
	eachVariant(t, func(t *testing.T, v variant) {
		f := mustParse(t, elfgen.Build(spec(v)))
		if s, ok, err := f.Interpreter(); s != "/lib64/ld-linux-x86-64.so.2" || !ok || err != nil {
			t.Fatal(s, ok, err)
		}
		if n, err := f.Needed(); err != nil || !slices.Equal(n, spec(v).Needed) {
			t.Fatal(n, err)
		}
		if s, ok, _ := f.Soname(); s != "libself.so.2" || !ok {
			t.Fatal(s)
		}
		if s, ok, _ := f.Runpath(); s != spec(v).Rpath || !ok {
			t.Fatal(s)
		}
		if _, ok, _ := f.Rpath(); ok {
			t.Fatal("DT_RPATH reported")
		}
		if f.Class != v.class {
			t.Fatal(f.Class)
		}
	})
}

func TestNoInterpNoDynamic(t *testing.T) {
	s := spec(variants[0])
	s.Interp = ""
	f := mustParse(t, elfgen.Build(s))
	if _, ok, _ := f.Interpreter(); ok {
		t.Fatal("interp")
	}
	if _, err := f.SetInterpreter("/x"); !errors.Is(err, ErrNoInterp) {
		t.Fatal(err)
	}
	// No program headers at all.
	b := elfgen.Build(s)
	binary.LittleEndian.PutUint16(b[56:], 0)
	g := mustParse(t, b)
	if _, err := g.SetRpath("x", false); !errors.Is(err, ErrNoDynamic) {
		t.Fatal(err)
	}
	if n, err := g.Needed(); err != nil || len(n) != 0 {
		t.Fatal(n, err)
	}
}

func TestSetInterpreter(t *testing.T) {
	eachVariant(t, func(t *testing.T, v variant) {
		orig := elfgen.Build(spec(v))
		p := write(t, orig)
		cs, err := SetInterpreter(p, "/nix/store/ld.so", Options{})
		if err != nil || len(cs) != 1 {
			t.Fatal(cs, err)
		}
		got, _ := os.ReadFile(p)
		f := mustParse(t, got)
		if s, _, _ := f.Interpreter(); s != "/nix/store/ld.so" {
			t.Fatal(s)
		}
		// zero padded to the slot, nothing else moved
		po := f.interp
		if !bytes.Equal(got[po.off+uint64(len("/nix/store/ld.so")):po.off+po.filesz], make([]byte, po.filesz-uint64(len("/nix/store/ld.so")))) {
			t.Fatal("slot not zero padded")
		}
		if err := verify(orig, got, &File{data: got, allowed: []rng{{po.off, po.off + po.filesz}}, touched: tInterp}); err != nil {
			t.Fatal(err)
		}
		// same value: no change, no write
		if cs, err := SetInterpreter(p, "/nix/store/ld.so", Options{}); err != nil || cs != nil {
			t.Fatal(cs, err)
		}
	})
}

func TestSetInterpreterNoSpace(t *testing.T) {
	orig := elfgen.Build(spec(variants[0]))
	p := write(t, orig)
	long := "/" + string(bytes.Repeat([]byte("a"), 60))
	_, err := SetInterpreter(p, long, Options{})
	var ns *NoSpaceError
	if !errors.Is(err, ErrNoSpace) || !errors.As(err, &ns) || ns.Have != 40 || ns.Need != uint64(len(long))+1 || ns.Error() == "" {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(p); !bytes.Equal(got, orig) {
		t.Fatal("file changed on refusal")
	}
	// exactly full is fine: 39 chars + NUL = 40
	if _, err := SetInterpreter(p, "/"+string(bytes.Repeat([]byte("b"), 38)), Options{}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "a\x00b"} {
		if _, err := SetInterpreter(p, bad, Options{}); err == nil {
			t.Fatal("accepted", bad)
		}
	}
}

func TestSetRpath(t *testing.T) {
	eachVariant(t, func(t *testing.T, v variant) {
		orig := elfgen.Build(spec(v))
		p := write(t, orig)
		cs, err := SetRpath(p, "$ORIGIN/../lib", false, Options{})
		if err != nil || len(cs) != 1 {
			t.Fatal(cs, err)
		}
		f, err := Open(p)
		if err != nil {
			t.Fatal(err)
		}
		if s, _, _ := f.SearchPath(); s != "$ORIGIN/../lib" {
			t.Fatal(s)
		}
		if n, _ := f.Needed(); !slices.Equal(n, spec(v).Needed) {
			t.Fatal(n)
		}
		// force converts to DT_RPATH
		cs, err = SetRpath(p, "/a", true, Options{})
		if err != nil || len(cs) != 2 {
			t.Fatal(cs, err)
		}
		f, _ = Open(p)
		if s, ok, _ := f.Rpath(); s != "/a" || !ok {
			t.Fatal(s)
		}
		if _, ok, _ := f.Runpath(); ok {
			t.Fatal("RUNPATH kept")
		}
		// and back
		if _, err = SetRpath(p, "/a", false, Options{}); err != nil {
			t.Fatal(err)
		}
		f, _ = Open(p)
		if s, ok, _ := f.Runpath(); s != "/a" || !ok {
			t.Fatal(s)
		}
	})
}

func TestSetRpathErrors(t *testing.T) {
	s := spec(variants[0])
	orig := elfgen.Build(s)
	p := write(t, orig)
	if _, err := SetRpath(p, string(bytes.Repeat([]byte("x"), 61)), false, Options{}); !errors.Is(err, ErrNoSpace) {
		t.Fatal(err)
	}
	// slot is len(old): the old value is 49 bytes though the slot was padded
	// to 60 in the file; the usable slot is the string, as zpkb defines it.
	if _, err := SetRpath(p, string(bytes.Repeat([]byte("x"), 49)), false, Options{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(p); len(got) != len(orig) {
		t.Fatal("length changed")
	}
	// no entry
	s.Rpath, s.RpathSlot = "", 0
	p2 := write(t, elfgen.Build(s))
	if _, err := SetRpath(p2, "/x", false, Options{}); !errors.Is(err, ErrNoRpath) {
		t.Fatal(err)
	}
	if cs, err := RemoveRpath(p2, Options{}); err != nil || cs != nil {
		t.Fatal(cs, err)
	}
	if _, err := SetRpath(p, "a\x00", false, Options{}); err == nil {
		t.Fatal("NUL accepted")
	}
}

func TestBothRpathAndRunpath(t *testing.T) {
	b := elfgen.Build(spec(variants[0]))
	f := mustParse(t, b)
	// turn the last needed into a second path tag: DT_NEEDED(1) -> DT_RPATH(15)
	i, _ := f.firstDyn(dtNeeded)
	binary.LittleEndian.PutUint64(b[f.dyn[i].off:], dtRpath)
	g := mustParse(t, b)
	if _, err := g.SetRpath("x", false); !errors.Is(err, ErrAmbiguous) {
		t.Fatal(err)
	}
}

func TestRemoveRpath(t *testing.T) {
	eachVariant(t, func(t *testing.T, v variant) {
		p := write(t, elfgen.Build(spec(v)))
		// set to empty: the entry stays, empty (patchelf's behaviour)
		q := write(t, elfgen.Build(spec(v)))
		if _, err := SetRpath(q, "", false, Options{}); err != nil {
			t.Fatal(err)
		}
		if g, _ := Open(q); func() bool { s, ok, _ := g.SearchPath(); return s != "" || !ok }() {
			t.Fatal("empty rpath not kept as an empty entry")
		}
		cs, err := RemoveRpath(p, Options{})
		if err != nil || len(cs) != 1 {
			t.Fatal(cs, err)
		}
		f, _ := Open(p)
		if _, ok, _ := f.SearchPath(); ok {
			t.Fatal("still there")
		}
		if n, _ := f.Needed(); !slices.Equal(n, spec(v).Needed) {
			t.Fatal(n)
		}
		if s, _, _ := f.Soname(); s != "libself.so.2" {
			t.Fatal(s)
		}
	})
}

func TestRemoveNeeded(t *testing.T) {
	eachVariant(t, func(t *testing.T, v variant) {
		p := write(t, elfgen.Build(spec(v)))
		cs, err := RemoveNeeded(p, "libm.so.6", Options{})
		if err != nil || len(cs) != 1 {
			t.Fatal(cs, err)
		}
		f, _ := Open(p)
		if n, _ := f.Needed(); !slices.Equal(n, []string{"libfoo.so.1", "libc.so.6"}) {
			t.Fatal(n)
		}
		if s, _, _ := f.SearchPath(); s != spec(v).Rpath {
			t.Fatal(s)
		}
		if cs, err := RemoveNeeded(p, "libnothere.so", Options{}); err != nil || cs != nil {
			t.Fatal(cs, err)
		}
		// remove all; the dynamic array stays terminated
		RemoveNeeded(p, "libfoo.so.1", Options{})
		RemoveNeeded(p, "libc.so.6", Options{})
		f, _ = Open(p)
		if n, _ := f.Needed(); len(n) != 0 {
			t.Fatal(n)
		}
		if s, _, _ := f.Soname(); s != "libself.so.2" {
			t.Fatal(s)
		}
	})
}

func TestReplaceNeeded(t *testing.T) {
	eachVariant(t, func(t *testing.T, v variant) {
		p := write(t, elfgen.Build(spec(v)))
		if _, err := ReplaceNeeded(p, "libfoo.so.1", "libbar.so.1", Options{}); err != nil {
			t.Fatal(err)
		}
		f, _ := Open(p)
		if n, _ := f.Needed(); !slices.Equal(n, []string{"libbar.so.1", "libm.so.6", "libc.so.6"}) {
			t.Fatal(n)
		}
		if _, err := ReplaceNeeded(p, "libm.so.6", "libmuchlonger.so.6", Options{}); !errors.Is(err, ErrNoSpace) {
			t.Fatal(err)
		}
		if cs, err := ReplaceNeeded(p, "libm.so.6", "libm.so.6", Options{}); err != nil || cs != nil {
			t.Fatal(cs, err)
		}
		if _, err := ReplaceNeeded(p, "libm.so.6", "", Options{}); err == nil {
			t.Fatal("empty accepted")
		}
	})
}

func TestSharedTailRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(*elfgen.Spec)
	}{
		{"needed", func(s *elfgen.Spec) { s.TailNeeded = 6 }},
		{"dynsym", func(s *elfgen.Spec) { s.TailSymbol = 6 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := spec(variants[0])
			tc.mod(&s)
			orig := elfgen.Build(s)
			p := write(t, orig)
			if _, err := SetRpath(p, "/short", false, Options{}); !errors.Is(err, ErrAmbiguous) {
				t.Fatal(err)
			}
			if got, _ := os.ReadFile(p); !bytes.Equal(got, orig) {
				t.Fatal("changed")
			}
		})
	}
}

func TestSharedStringBetweenEntries(t *testing.T) {
	// two DT_NEEDED with the same string offset are replaced together
	b := elfgen.Build(elfgen.Spec{Needed: []string{"liba.so"}, Rpath: "/x"})
	f := mustParse(t, b)
	i, _ := f.firstDyn(dtNeeded)
	// copy NEEDED into the free slot after the last entry
	last := f.dyn[len(f.dyn)-1].off + f.entSize
	copy(b[last:], b[f.dyn[i].off:f.dyn[i].off+f.entSize])
	g := mustParse(t, b)
	cs, err := g.ReplaceNeeded("liba.so", "libb.so")
	if err != nil || len(cs) != 1 {
		t.Fatal(cs, err)
	}
	if n, _ := g.Needed(); !slices.Equal(n, []string{"libb.so", "libb.so"}) {
		t.Fatal(n)
	}
}

func TestPatchWorkflow(t *testing.T) {
	orig := elfgen.Build(spec(variants[0]))
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	os.WriteFile(real, orig, 0o751)
	os.Chmod(real, 0o751|os.ModeSetuid)
	os.Symlink("real", link)

	// dry run writes nothing
	cs, err := SetRpath(link, "/d", false, Options{DryRun: true})
	if err != nil || len(cs) != 1 {
		t.Fatal(cs, err)
	}
	if got, _ := os.ReadFile(real); !bytes.Equal(got, orig) {
		t.Fatal("dry run wrote")
	}
	// real run through the symlink: link survives, mode preserved
	if _, err := SetRpath(link, "/d", false, Options{}); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Lstat(link); st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink replaced")
	}
	st, _ := os.Stat(real)
	if st.Mode() != orig0(0o751) {
		t.Fatalf("mode %v", st.Mode())
	}
	// no temp files left behind
	ents, _ := os.ReadDir(dir)
	if len(ents) != 2 {
		t.Fatal(ents)
	}
	// --output
	out := filepath.Join(dir, "out")
	if _, err := SetRpath(real, "/e", false, Options{Output: out}); err != nil {
		t.Fatal(err)
	}
	f, _ := Open(out)
	if s, _, _ := f.SearchPath(); s != "/e" {
		t.Fatal(s)
	}
	// errors
	if _, err := SetRpath(filepath.Join(dir, "missing"), "/x", false, Options{}); err == nil {
		t.Fatal("missing")
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("directory")
	}
	txt := write(t, []byte("hello world, not an elf"))
	if _, err := SetRpath(txt, "/x", false, Options{}); !errors.Is(err, ErrNotELF) {
		t.Fatal(err)
	}
	if _, err := SetRpath(real, "/x", false, Options{Output: filepath.Join(dir, "no", "such", "out")}); err == nil {
		t.Fatal("unwritable output")
	}
}

func orig0(m os.FileMode) os.FileMode { return m&os.ModePerm | os.ModeSetuid }

func TestVerifyRefusesStrayBytes(t *testing.T) {
	orig := elfgen.Build(spec(variants[0]))
	f := mustParse(t, slices.Clone(orig))
	if _, err := f.SetRpath("/q", false); err != nil {
		t.Fatal(err)
	}
	if err := verify(orig, f.data, f); err != nil {
		t.Fatal(err)
	}
	f.data[0x41] ^= 0xff // a byte nobody declared
	if err := verify(orig, f.data, f); !errors.Is(err, ErrVerify) {
		t.Fatal(err)
	}
	f.data[0x41] ^= 0xff
	f.data = f.data[:len(f.data)-1]
	if err := verify(orig, f.data, f); !errors.Is(err, ErrVerify) {
		t.Fatal(err)
	}
	// declared-but-wrong: a changed field the edit did not claim to touch
	g := mustParse(t, slices.Clone(orig))
	g.SetRpath("/q", false)
	g.touched = 0
	if err := verify(orig, g.data, g); !errors.Is(err, ErrVerify) {
		t.Fatal(err)
	}
	// header class flipped
	h := mustParse(t, slices.Clone(orig))
	h.allowed = []rng{{0, uint64(len(orig))}}
	h.data[16]++
	if err := verify(orig, h.data, h); !errors.Is(err, ErrVerify) {
		t.Fatal(err)
	}
	// the bytes on disk are not the bytes the editor meant to write
	w := mustParse(t, slices.Clone(orig))
	w.SetRpath("/q", false)
	out := slices.Clone(w.data)
	out[w.merged()[0].off] ^= 0xff
	if err := verify(orig, out, w); !errors.Is(err, ErrVerify) {
		t.Fatal(err)
	}
	// range beyond the file
	k := mustParse(t, slices.Clone(orig))
	k.allowed = []rng{{0, uint64(len(orig)) + 1}}
	if err := verify(orig, k.data, k); !errors.Is(err, ErrVerify) {
		t.Fatal(err)
	}
}

func TestShrinkRpath(t *testing.T) {
	eachVariant(t, func(t *testing.T, v variant) {
		dir := t.TempDir()
		lib := filepath.Join(dir, "lib")
		other := filepath.Join(dir, "other")
		empty := filepath.Join(dir, "empty")
		wrong := filepath.Join(dir, "wrongarch")
		for _, d := range []string{lib, other, empty, wrong} {
			os.Mkdir(d, 0o755)
		}
		libfoo := elfgen.Build(elfgen.Spec{Class: v.class, BigEndian: v.big})
		os.WriteFile(filepath.Join(lib, "libfoo.so.1"), libfoo, 0o644)
		os.WriteFile(filepath.Join(other, "libfoo.so.1"), libfoo, 0o644) // second provider: unused
		os.WriteFile(filepath.Join(other, "libm.so.6"), libfoo, 0o644)
		os.WriteFile(filepath.Join(wrong, "libc.so.6"), elfgen.Build(elfgen.Spec{Class: v.class, BigEndian: v.big, Machine: 40}), 0o644)
		os.WriteFile(filepath.Join(wrong, "junk"), []byte("x"), 0o644)

		s := spec(v)
		// the origin is the binary's own directory: $ORIGIN/lib
		s.Rpath = "$ORIGIN/lib:" + empty + ":" + other + ":" + wrong + ":$ORIGIN/lib:$LIB/x:"
		s.RpathSlot = len(s.Rpath) + 20
		bin := filepath.Join(dir, "bin")
		os.WriteFile(bin, elfgen.Build(s), 0o755)
		cs, err := ShrinkRpath(bin, Options{})
		if err != nil || len(cs) == 0 {
			t.Fatal(cs, err)
		}
		f, _ := Open(bin)
		got, _, _ := f.SearchPath()
		// libfoo -> $ORIGIN/lib, libm -> other; empty, wrong (other arch) and the duplicate go;
		// the unjudgeable $LIB entry and the empty (cwd) entry stay.
		want := "$ORIGIN/lib:" + other + ":$LIB/x:"
		if got != want {
			t.Fatalf("got %q want %q", got, want)
		}
		// idempotent
		if cs, err := ShrinkRpath(bin, Options{}); err != nil || cs != nil {
			t.Fatal(cs, err)
		}
		// no rpath: nothing to do
		s.Rpath, s.RpathSlot = "", 0
		nb := filepath.Join(dir, "norpath")
		os.WriteFile(nb, elfgen.Build(s), 0o755)
		if cs, err := ShrinkRpath(nb, Options{}); err != nil || cs != nil {
			t.Fatal(cs, err)
		}
	})
}

func TestChangeString(t *testing.T) {
	if (Change{"rpath", "a", "b"}).String() == "" || tagName(7) != "7" || tagName(dtRpath) != "DT_RPATH" {
		t.Fatal("string")
	}
}

func TestParseErrors(t *testing.T) {
	good := elfgen.Build(spec(variants[0]))
	good32 := elfgen.Build(spec(variants[2]))
	mut := func(b []byte, fn func([]byte)) []byte { c := slices.Clone(b); fn(c); return c }
	le := binary.LittleEndian
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrNotELF},
		{"text", []byte("#!/bin/sh\necho hi\n"), ErrNotELF},
		{"bad class", mut(good, func(b []byte) { b[4] = 3 }), ErrCorrupt},
		{"bad data", mut(good, func(b []byte) { b[5] = 0 }), ErrCorrupt},
		{"bad version", mut(good, func(b []byte) { b[6] = 2 }), ErrCorrupt},
		{"truncated 64", good[:40], ErrCorrupt},
		{"truncated 32", good32[:40], ErrCorrupt},
		{"xnum", mut(good, func(b []byte) { le.PutUint16(b[56:], 0xffff) }), ErrUnsupported},
		{"phentsize", mut(good, func(b []byte) { le.PutUint16(b[54:], 55) }), ErrCorrupt},
		{"phoff overflow", mut(good, func(b []byte) { le.PutUint64(b[32:], ^uint64(0)-8) }), ErrCorrupt},
		{"phoff past end", mut(good, func(b []byte) { le.PutUint64(b[32:], uint64(len(b))) }), ErrCorrupt},
		{"segment past end", mut(good, func(b []byte) { le.PutUint64(b[64+56+32:], uint64(len(b))) }), ErrCorrupt},
		{"segment overflow", mut(good, func(b []byte) { le.PutUint64(b[64+56+8:], ^uint64(0)); le.PutUint64(b[64+56+32:], 2) }), ErrCorrupt},
		{"empty interp", mut(good, func(b []byte) { le.PutUint64(b[64+56+32:], 0) }), ErrCorrupt},
		{"strtab outside", mut(good, func(b []byte) { setDyn(t, b, dtStrtab, 0xdead0000) }), ErrCorrupt},
		{"strsz too big", mut(good, func(b []byte) { setDyn(t, b, dtStrsz, 1<<40) }), ErrCorrupt},
		{"no strsz", mut(good, func(b []byte) { setDynTag(t, b, dtStrsz, 0x70000000) }), ErrCorrupt},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse(c.in); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

// setDyn / setDynTag edit a 64-bit little-endian generated image.
func setDyn(t *testing.T, b []byte, tag int64, val uint64) {
	t.Helper()
	f := mustParse(t, slices.Clone(b))
	i, ok := f.firstDyn(tag)
	if !ok {
		t.Fatal("no tag", tag)
	}
	binary.LittleEndian.PutUint64(b[f.dyn[i].off+8:], val)
}

func setDynTag(t *testing.T, b []byte, tag int64, to uint64) {
	t.Helper()
	f := mustParse(t, slices.Clone(b))
	i, _ := f.firstDyn(tag)
	binary.LittleEndian.PutUint64(b[f.dyn[i].off:], to)
}

func TestCorruptStrings(t *testing.T) {
	good := elfgen.Build(spec(variants[0]))
	f := mustParse(t, good)
	// a NEEDED pointing past .dynstr
	b := slices.Clone(good)
	i, _ := f.firstDyn(dtNeeded)
	binary.LittleEndian.PutUint64(b[f.dyn[i].off+8:], 1<<30)
	g := mustParse(t, b)
	if _, err := SetRpath(write(t, b), "/x", false, Options{}); !errors.Is(err, ErrCorrupt) {
		t.Fatal("Patch edited a file whose other fields cannot be read:", err)
	}
	if _, err := g.Needed(); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	if _, err := g.RemoveNeeded("x"); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	if _, err := g.ReplaceNeeded("x", "y"); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	if _, err := g.ShrinkRpath("/"); err != nil && !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	// unterminated string: fill the tail of .dynstr with non-NUL
	c := slices.Clone(good)
	h := mustParse(t, c)
	for k := h.strOff; k < h.strOff+h.strLen; k++ {
		if c[k] == 0 {
			c[k] = 'x'
		}
	}
	u := mustParse(t, c)
	if _, err := u.Needed(); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	// unterminated interpreter
	d := slices.Clone(good)
	p := mustParse(t, d).interp
	for k := p.off; k < p.off+p.filesz; k++ {
		d[k] = 'x'
	}
	v := mustParse(t, d)
	if _, _, err := v.Interpreter(); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	if _, err := v.SetInterpreter("/y"); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	// snapshots surface corruption too
	if _, err := v.snap(); err == nil {
		t.Fatal("snap")
	}
	if _, err := u.snap(); err == nil {
		t.Fatal("snap")
	}
}

func TestSymCountVariants(t *testing.T) {
	good := elfgen.Build(spec(variants[0]))
	f := mustParse(t, good)
	// DT_HASH -> unknown tag: sizing falls back to the gap before .dynstr, which
	// here FOLLOWS nothing (strtab is before symtab): refused, not guessed.
	b := slices.Clone(good)
	setDynTag(t, b, dtHash, 0x70000000)
	if _, err := mustParse(t, b).SetRpath("/z", false); !errors.Is(err, ErrAmbiguous) {
		t.Fatal(err)
	}
	// gap form: pretend .dynsym precedes .dynstr
	symV, _ := f.dynVal(dtSymtab)
	g := mustParse(t, slices.Clone(b))
	g.dyn[mustIdx(t, g, dtStrtab)].val = symV + 24*3
	if n, err := g.symCount(symV); err != nil || n != 3 {
		t.Fatal(n, err)
	}
	g32 := mustParse(t, elfgen.Build(spec(variants[2])))
	g32.dyn[mustIdx(t, g32, dtHash)].tag = 0x70000000
	g32.dyn[mustIdx(t, g32, dtStrtab)].val = 16*5 + mustVal(t, g32, dtSymtab)
	if n, err := g32.symCount(mustVal(t, g32, dtSymtab)); err != nil || n != 5 {
		t.Fatal(n, err)
	}
	// DT_HASH outside any segment / file
	h := mustParse(t, slices.Clone(good))
	h.dyn[mustIdx(t, h, dtHash)].val = 0xdead0000
	if _, err := h.symCount(0); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	h2 := mustParse(t, slices.Clone(good))
	h2.data = h2.data[:int(mustOff(t, h2, dtHash))+2]
	if _, err := h2.symCount(0); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	// symtab pointing nowhere
	s2 := mustParse(t, slices.Clone(good))
	s2.dyn[mustIdx(t, s2, dtSymtab)].val = 0xdead0000
	if _, err := s2.SetRpath("/z", false); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	// symtab count beyond the file
	s3 := mustParse(t, slices.Clone(good))
	hv, _ := s3.vaddrToOff(mustVal(t, s3, dtHash))
	binary.LittleEndian.PutUint32(s3.data[hv+4:], 1<<24)
	if _, err := s3.SetRpath("/z", false); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
}

func mustIdx(t *testing.T, f *File, tag int64) int {
	t.Helper()
	i, ok := f.firstDyn(tag)
	if !ok {
		t.Fatal("no tag", tag)
	}
	return i
}
func mustVal(t *testing.T, f *File, tag int64) uint64 { return f.dyn[mustIdx(t, f, tag)].val }
func mustOff(t *testing.T, f *File, tag int64) uint64 {
	o, _ := f.vaddrToOff(mustVal(t, f, tag))
	return o
}

func TestGnuHashSizing(t *testing.T) {
	// A DT_GNU_HASH table with 1 bucket, symoffset 1, bloom 1, chains 3 long
	// (last has the stop bit): 4 symbols in total.
	for _, v := range []variant{variants[0], variants[3]} {
		s := spec(v)
		s.Symbols = []string{"a", "b", "c", "d", "e", "f", "g", "h"} // room for the rewritten table
		b := elfgen.Build(s)
		f := mustParse(t, b)
		hOff := mustOff(t, f, dtHash)
		w := uint64(f.Class / 8)
		// rewrite the hash table in place (DT_HASH area has room for 3+nsym words = 6 words)
		o := f.Order
		o.PutUint32(b[hOff:], 1)   // nbuckets
		o.PutUint32(b[hOff+4:], 1) // symoffset
		o.PutUint32(b[hOff+8:], 0) // bloom size 0
		o.PutUint32(b[hOff+12:], 0)
		buckets := hOff + 16 + 0*w
		o.PutUint32(b[buckets:], 2) // bucket -> symbol 2
		chains := buckets + 4
		o.PutUint32(b[chains:], 0)   // symbol 1
		o.PutUint32(b[chains+4:], 0) // symbol 2
		o.PutUint32(b[chains+8:], 1) // symbol 3, stop
		// switch tag DT_HASH -> DT_GNU_HASH
		hi := mustIdx(t, f, dtHash)
		if f.Class == 64 {
			o.PutUint64(b[f.dyn[hi].off:], dtGnuHash)
		} else {
			o.PutUint32(b[f.dyn[hi].off:], uint32(dtGnuHash&0xffffffff))
		}
		g := mustParse(t, b)
		if n, err := g.symCount(mustVal(t, g, dtSymtab)); err != nil || n != 4 {
			t.Fatal(v.name, n, err)
		}
		// no hashed symbols: bucket 0 -> count is symoffset
		o.PutUint32(b[buckets:], 0)
		if n, err := mustParse(t, b).symCount(mustVal(t, g, dtSymtab)); err != nil || n != 1 {
			t.Fatal(n, err)
		}
		// chain running off the file
		o.PutUint32(b[buckets:], 2)
		o.PutUint32(b[chains+8:], 0)
		o.PutUint32(b[buckets:], 1<<20)
		if _, err := mustParse(t, b).symCount(mustVal(t, g, dtSymtab)); !errors.Is(err, ErrCorrupt) {
			t.Fatal(err)
		}
		// header past the end of the file
		g2 := mustParse(t, b)
		g2.data = g2.data[:hOff+6]
		if _, err := g2.symCount(0); !errors.Is(err, ErrCorrupt) {
			t.Fatal(err)
		}
		g3 := mustParse(t, b)
		g3.dyn[mustIdx(t, g3, dtGnuHash)].val = 0xdead0000
		if _, err := g3.symCount(0); !errors.Is(err, ErrCorrupt) {
			t.Fatal(err)
		}
		// buckets past the end
		g4 := mustParse(t, b)
		o.PutUint32(g4.data[hOff:], 1<<28)
		if _, err := g4.symCount(0); !errors.Is(err, ErrCorrupt) {
			t.Fatal(err)
		}
	}
}

func TestVersionTables(t *testing.T) {
	// Build an image with a DT_VERNEED and DT_VERDEF appended inside the
	// segment, naming strings that sit inside the rpath slot.
	for _, big := range []bool{false, true} {
		s := spec(variant{"x", 64, big})
		b := elfgen.Build(s)
		f := mustParse(t, b)
		o := f.Order
		rp, _, _ := f.Runpath()
		_ = rp
		rpOff := mustVal(t, f, dtRunpath)
		// place tables at the tail of the file (extend the image + segment)
		tail := uint64(len(b))
		b = append(b, make([]byte, 128)...)
		// Verneed @tail: cnt 1, file -> 0 (empty), aux 16, next 0 ; Vernaux name -> inside rpath
		o.PutUint16(b[tail+2:], 1)
		o.PutUint32(b[tail+4:], 0)
		o.PutUint32(b[tail+8:], 16)
		o.PutUint32(b[tail+12:], 0)
		o.PutUint32(b[tail+16+8:], uint32(rpOff+5))
		o.PutUint32(b[tail+16+12:], 0)
		// Verdef @tail+64: cnt 1, aux 20, next 0 ; Verdaux name -> inside rpath
		o.PutUint16(b[tail+64+6:], 1)
		o.PutUint32(b[tail+64+12:], 20)
		o.PutUint32(b[tail+64+16:], 0)
		o.PutUint32(b[tail+64+20:], uint32(rpOff+7))
		o.PutUint32(b[tail+64+24:], 0)
		// grow PT_LOAD to cover it and add the tags into the free dynamic slots
		le := f.Order
		ph0 := uint64(64)
		le.PutUint64(b[ph0+32:], uint64(len(b)))
		le.PutUint64(b[ph0+40:], uint64(len(b)))
		free := f.dyn[len(f.dyn)-1].off + 16
		put := func(i uint64, tag, val uint64) {
			le.PutUint64(b[free+i*16:], tag)
			le.PutUint64(b[free+i*16+8:], val)
		}
		put(0, dtVerneed, 0x400000+tail)
		put(1, dtVerneedN, 1)
		// no more room for VERDEF in 3 free slots with the terminator: replace
		// DT_SYMENT (11), which we do not need, and reuse the third slot
		si := mustIdx(t, f, 11)
		le.PutUint64(b[f.dyn[si].off:], dtVerdef)
		le.PutUint64(b[f.dyn[si].off+8:], 0x400000+tail+64)
		put(1, dtVerdefN, 1)
		put(0, dtVerneed, 0x400000+tail)
		// VERNEEDN lost its slot: it defaults to 0 entries, so test VERNEED via
		// verdef only, then verneed separately below.
		g := mustParse(t, slices.Clone(b))
		if _, err := g.SetRpath("/short", false); !errors.Is(err, ErrAmbiguous) {
			t.Fatal("verdef alias not detected:", err)
		}
		// the walkers themselves
		var seen []uint64
		if err := g.walkVer(0x400000+tail, 1, func(r uint64) { seen = append(seen, r) }); err != nil || len(seen) != 2 || seen[1] != rpOff+5 {
			t.Fatal(seen, err)
		}
		if err := g.walkDef(0x400000+tail+64, 1, func(r uint64) { seen = append(seen, r) }); err != nil || seen[len(seen)-1] != rpOff+7 {
			t.Fatal(seen, err)
		}
		// bad addresses / loops
		if err := g.walkVer(0xdead0000, 1, func(uint64) {}); !errors.Is(err, ErrCorrupt) {
			t.Fatal(err)
		}
		if err := g.walkDef(0xdead0000, 1, func(uint64) {}); !errors.Is(err, ErrCorrupt) {
			t.Fatal(err)
		}
		if err := g.walkVer(0x400000+tail+120, 2, func(uint64) {}); !errors.Is(err, ErrCorrupt) {
			t.Fatal(err)
		}
		if err := g.walkDef(0x400000+tail+120, 2, func(uint64) {}); !errors.Is(err, ErrCorrupt) {
			t.Fatal(err)
		}
		// chains: next pointing outside, aux outside
		h := slices.Clone(b)
		o.PutUint32(h[tail+12:], 1<<20) // vn_next, with num=2 walks off
		hg := mustParse(t, h)
		if err := hg.walkVer(0x400000+tail, 2, func(uint64) {}); !errors.Is(err, ErrCorrupt) {
			t.Fatal(err)
		}
		h = slices.Clone(b)
		o.PutUint32(h[tail+8:], 1<<20) // vn_aux outside
		if err := mustParse(t, h).walkVer(0x400000+tail, 1, func(uint64) {}); !errors.Is(err, ErrCorrupt) {
			t.Fatal(err)
		}
		h = slices.Clone(b)
		o.PutUint32(h[tail+64+20+4:], 1<<20) // vda_next points outside the file
		o.PutUint16(h[tail+64+6:], 2)
		if err := mustParse(t, h).walkDef(0x400000+tail+64, 1, func(uint64) {}); !errors.Is(err, ErrCorrupt) {
			t.Fatal(err)
		}
		h = slices.Clone(b)
		o.PutUint32(h[tail+64+12:], 1<<20)
		if err := mustParse(t, h).walkDef(0x400000+tail+64, 1, func(uint64) {}); !errors.Is(err, ErrCorrupt) {
			t.Fatal(err)
		}
		h = slices.Clone(b)
		o.PutUint32(h[tail+64+16:], 1<<20)
		o.PutUint32(h[tail+64+20+4:], 0)
		if err := mustParse(t, h).walkDef(0x400000+tail+64, 2, func(uint64) {}); !errors.Is(err, ErrCorrupt) {
			t.Fatal(err)
		}
		// vernaux chain with a next link
		h = slices.Clone(b)
		o.PutUint16(h[tail+2:], 2)
		o.PutUint32(h[tail+16+12:], 16)
		if err := mustParse(t, h).walkVer(0x400000+tail, 1, func(uint64) {}); err != nil {
			t.Fatal(err)
		}
		// verneed next link followed
		h = slices.Clone(b)
		o.PutUint32(h[tail+12:], 40)
		if err := mustParse(t, h).walkVer(0x400000+tail, 2, func(uint64) {}); err != nil {
			t.Fatal(err)
		}
		// verdef: next + aux next links followed
		h = slices.Clone(b)
		o.PutUint16(h[tail+64+6:], 2)
		o.PutUint32(h[tail+64+20+4:], 8)
		o.PutUint32(h[tail+64+16:], 40)
		if err := mustParse(t, h).walkDef(0x400000+tail+64, 2, func(uint64) {}); err != nil && !errors.Is(err, ErrCorrupt) {
			t.Fatal(err)
		}
	}
}

func TestPatchOnNonRegular(t *testing.T) {
	if _, err := Patch(t.TempDir(), Options{}, func(*File) ([]Change, error) { return nil, nil }); err == nil {
		t.Fatal("directory accepted")
	}
	p := write(t, elfgen.Build(spec(variants[0])))
	boom := errors.New("boom")
	if _, err := Patch(p, Options{}, func(*File) ([]Change, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if cs, err := Patch(p, Options{}, func(*File) ([]Change, error) { return nil, nil }); err != nil || cs != nil {
		t.Fatal(cs, err)
	}
}
