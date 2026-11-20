package elfpatch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"testing"

	"github.com/go-binfmt/elfpatch/internal/elfgen"
)

func TestGrowthEditGuards(t *testing.T) {
	base := elfgen.LSpec{Interp: "/lib/ld.so.1", Needed: []string{"libm.so.6"}, Soname: "libx.so.1"}
	t.Run("an empty rpath where there is none is nothing to do", func(t *testing.T) {
		img := elfgen.BuildLayout(base)
		f := mustParse(t, slices.Clone(img))
		cs, err := f.SetRpath("", false)
		if err != nil || len(cs) != 0 || f.grown || !bytes.Equal(f.data, img) {
			t.Fatal(cs, err, f.grown)
		}
	})
	t.Run("no dynamic segment", func(t *testing.T) {
		b := elfgen.BuildLayout(base)
		binary.LittleEndian.PutUint16(b[56:], 0) // no program headers
		f := mustParse(t, b)
		if _, err := f.SetSoname("x"); !errors.Is(err, ErrNoDynamic) {
			t.Fatal(err)
		}
		if _, err := f.AddNeeded("libz.so"); !errors.Is(err, ErrNoDynamic) {
			t.Fatal(err)
		}
		if _, err := f.AddRpath("/b", false); !errors.Is(err, ErrNoDynamic) {
			t.Fatal(err)
		}
	})
	t.Run("invalid names", func(t *testing.T) {
		f := mustParse(t, elfgen.BuildLayout(base))
		if _, err := f.SetSoname("a\x00b"); err == nil {
			t.Fatal("a NUL in a soname was accepted")
		}
		for _, bad := range []string{"", "a\x00b"} {
			if _, err := f.AddNeeded("libok.so", bad); err == nil {
				t.Fatalf("%q was accepted as a library name", bad)
			}
		}
		if cs, err := f.AddNeeded(); err != nil || cs != nil {
			t.Fatal("nothing to add is not a change:", cs, err)
		}
		if f.grown {
			t.Fatal("a refusal grew the file")
		}
	})
}

func TestGrowthVersionNeeds(t *testing.T) {
	spec := elfgen.LSpec{Exec: true, Interp: "/lib/ld.so.1", Needed: []string{"libm.so.6", "libc.so.6"}, Verneed: []string{"libm.so.6", "libc.so.6"}, Notes: true}
	for _, repl := range []string{"libm-with-a-longer-name.so.6", "libm.so.5", "m.so.6"} {
		out, cs := gpatch(t, elfgen.BuildLayout(spec), Options{}, func(f *File) ([]Change, error) { return f.ReplaceNeeded("libm.so.6", repl) })
		if len(cs) == 0 {
			t.Fatal("no change")
		}
		g := mustParse(t, out)
		if n, _ := g.Needed(); !slices.Equal(n, []string{repl, "libc.so.6"}) {
			t.Fatalf("needed %q", n)
		}
		_, vals, err := g.verneedFiles()
		if err != nil || len(vals) != 2 {
			t.Fatal(vals, err)
		}
		for i, want := range []string{repl, "libc.so.6"} {
			if s, err := g.strAt(vals[i]); err != nil || s != want {
				t.Fatalf("vn_file %d reads %q, want %q (%v)", i, s, want, err)
			}
		}
	}
	t.Run("a version-needed name is unrelated to a name that is absent", func(t *testing.T) {
		out, cs := gpatch(t, elfgen.BuildLayout(spec), Options{}, func(f *File) ([]Change, error) { return f.ReplaceNeeded("libabsent.so", "libx.so") })
		if len(cs) != 0 || out == nil {
			t.Fatal(cs)
		}
	})
	t.Run("verneedFiles on damaged tables", func(t *testing.T) {
		img := elfgen.BuildLayout(spec)
		g := mustParse(t, slices.Clone(img))
		if _, _, err := g.verneedFiles(); err != nil {
			t.Fatal(err)
		}
		h := mustParse(t, slices.Clone(img))
		h.dyn[mustIdx(t, h, dtVerneed)].val = 0xdead0000
		if _, _, err := h.verneedFiles(); !errors.Is(err, ErrCorrupt) {
			t.Fatal(err)
		}
		// a chain that runs off the end of the file
		k := mustParse(t, slices.Clone(img))
		at, _, _ := k.verneedFiles()
		binary.LittleEndian.PutUint32(k.data[at[0]+8:], 0x7ffffff0) // vn_next
		if _, _, err := k.verneedFiles(); !errors.Is(err, ErrCorrupt) {
			t.Fatal(err)
		}
		// a damaged table makes the edit refuse, not guess
		m := mustParse(t, slices.Clone(img))
		m.dyn[mustIdx(t, m, dtVerneed)].val = 0xdead0000
		if _, err := m.ReplaceNeeded("libm.so.6", "libm-longer-name.so.6"); err == nil {
			t.Fatal("a damaged version-needed table was edited")
		}
	})
	t.Run("version names outside .dynstr are refused", func(t *testing.T) {
		img := elfgen.BuildLayout(spec)
		l, _ := loadLayout(img, 0)
		i := l.find(".gnu.version_r")
		s := l.sh[i]
		s.link = uint32(l.find(".hash"))
		l.putShdr(img[l.shoff()+uint64(i)*l.shentsize():], s)
		f := mustParse(t, img)
		if _, err := f.ReplaceNeeded("libm.so.6", "libm-longer-name.so.6"); !errors.Is(err, ErrNoSpace) {
			t.Fatal(err)
		}
	})
}

func TestLayoutPrimitives(t *testing.T) {
	if roundUp(0, 8) != 8 || roundUp(1, 8) != 8 || roundUp(8, 8) != 8 || roundUp(9, 8) != 16 {
		t.Fatal("roundUp")
	}
	if _, err := loadLayout([]byte("not an elf file at all, just text"), 0); !errors.Is(err, ErrNotELF) {
		t.Fatal(err)
	}
	t.Run("PT_PHDR sorts first whatever its address", func(t *testing.T) {
		for _, in := range [][]phdr{
			{{typ: ptLoad, paddr: 0x1000}, {typ: ptPhdr, paddr: 0x9000}},
			{{typ: ptPhdr, paddr: 0x9000}, {typ: ptLoad, paddr: 0x1000}},
			{{typ: ptLoad, paddr: 0x3000}, {typ: ptLoad, paddr: 0x2000}, {typ: ptPhdr, paddr: 0x9000}},
		} {
			l := &layout{ph: slices.Clone(in)}
			l.sortPhdrs()
			if l.ph[0].typ != ptPhdr {
				t.Fatalf("%v sorted to %v", in, l.ph)
			}
		}
		l := &layout{ph: []phdr{{typ: ptLoad, paddr: 3}, {typ: ptLoad, paddr: 1}, {typ: ptLoad, paddr: 2}}}
		l.sortPhdrs()
		if l.ph[0].paddr != 1 || l.ph[1].paddr != 2 || l.ph[2].paddr != 3 {
			t.Fatal(l.ph)
		}
	})
	t.Run("shiftFile splits the segment it cuts and only that", func(t *testing.T) {
		img := elfgen.BuildLayout(elfgen.LSpec{Exec: true, Interp: "/lib/ld.so.1", Rpath: "/a"})
		l, _ := loadLayout(slices.Clone(img), 0)
		n := len(l.ph)
		// at a segment boundary nothing is cut
		if err := l.run(func() { l.shiftFile(1, 0x1000, 0) }); err != nil {
			t.Fatal(err)
		}
		if len(l.ph) != n || len(l.data) != len(img)+0x1000 {
			t.Fatalf("a shift at a boundary: %d headers (was %d), %d bytes (was %d)", len(l.ph), n, len(l.data), len(img))
		}
		// inside the first segment it is split in two
		l, _ = loadLayout(slices.Clone(img), 0)
		if err := l.run(func() { l.shiftFile(1, 0x100, 0x200) }); err != nil {
			t.Fatal(err)
		}
		if len(l.ph) != n+1 {
			t.Fatalf("a shift inside a segment: %d headers, want %d", len(l.ph), n+1)
		}
	})
	t.Run("nothing replaced, nothing rewritten", func(t *testing.T) {
		img := elfgen.BuildLayout(elfgen.LSpec{Exec: true, Interp: "/lib/ld.so.1", Rpath: "/a"})
		l, _ := loadLayout(slices.Clone(img), 0)
		if err := l.run(func() { l.rewriteSections() }); err != nil || !bytes.Equal(l.data, img) {
			t.Fatal(err)
		}
	})
	t.Run("cstr", func(t *testing.T) {
		l := &layout{data: []byte("\x00abc\x00xy")}
		cases := []struct {
			name string
			sec  shdr
			o    uint64
			want string
			ok   bool
		}{
			{"ok", shdr{typ: 3, off: 0, size: 5}, 1, "abc", true},
			{"empty string", shdr{typ: 3, off: 0, size: 5}, 0, "", true},
			{"offset at the end", shdr{typ: 3, off: 0, size: 5}, 5, "", false},
			{"unterminated", shdr{typ: 3, off: 0, size: 7}, 5, "", false},
			{"no contents", shdr{typ: shtNobits, off: 0, size: 5}, 1, "", false},
			{"outside the file", shdr{typ: 3, off: 4, size: 50}, 1, "", false},
		}
		for _, c := range cases {
			if s, ok := l.cstr(c.sec, c.o); s != c.want || ok != c.ok {
				t.Fatalf("%s: %q %v", c.name, s, ok)
			}
		}
	})
}

func TestVerifyGrownGuards(t *testing.T) {
	spec := elfgen.LSpec{Exec: true, Interp: "/lib/ld.so.1", Needed: []string{"libc.so.6"}, Soname: "libx.so", Rpath: "/a"}
	orig := elfgen.BuildLayout(spec)
	f := mustParse(t, slices.Clone(orig))
	if _, err := f.SetRpath(long(300), false); err != nil {
		t.Fatal(err)
	}
	if err := verifyGrown(orig, f.data, f); err != nil {
		t.Fatal(err)
	}
	t.Run("bytes that are not the editor's image", func(t *testing.T) {
		out := slices.Clone(f.data)
		out[len(out)-1] ^= 1
		wantMsg(t, verifyGrown(orig, out, f), ErrVerify, "differ")
	})
	t.Run("an input that does not parse", func(t *testing.T) {
		if err := verifyGrown([]byte("junk"), f.data, f); !errors.Is(err, ErrNotELF) {
			t.Fatal(err)
		}
	})
	t.Run("an output that does not parse", func(t *testing.T) {
		g := &File{data: []byte("junk that is not an ELF image")}
		wantMsg(t, verifyGrown(orig, g.data, g), ErrVerify, "does not parse")
	})
	// the same dynamic fields with and without section headers
	plain := elfgen.Build(elfgen.Spec{Interp: "/lib/ld.so.1", Needed: []string{"libc.so.6"}, Soname: "libx.so", Rpath: "/a"})
	lay := elfgen.BuildLayout(elfgen.LSpec{Interp: "/lib/ld.so.1", Needed: []string{"libc.so.6"}, Soname: "libx.so", Rpath: "/a"})
	t.Run("an input without section headers", func(t *testing.T) {
		g := &File{data: lay}
		if err := verifyGrown(plain, lay, g); !errors.Is(err, ErrUnsupported) {
			t.Fatal(err)
		}
	})
	t.Run("an output without section headers", func(t *testing.T) {
		g := &File{data: plain}
		wantMsg(t, verifyGrown(lay, plain, g), ErrVerify, "output layout")
	})
}
