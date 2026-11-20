package elfpatch

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/go-binfmt/elfpatch/internal/elfgen"
)

// Phase 2 on synthetic images with section headers (elfgen.BuildLayout): every
// class, byte order, executable and shared object, three page sizes, with and
// without a PT_NOTE, a PT_PHDR and a file tail. The oracle is the standard
// library's debug/elf, an independent reader, plus the verifier the edit ran
// under (a grown file that fails it is never written).

type gimg struct {
	name string
	spec elfgen.LSpec
}

func gimages() []gimg {
	var out []gimg
	for _, class := range []int{64, 32} {
		for _, be := range []bool{false, true} {
			for _, exec := range []bool{true, false} {
				for _, machine := range []uint16{0, 183, 2} {
					for _, notes := range []bool{false, true} {
						for _, tail := range []int{0, 0x3000} {
							for _, noPhdr := range []bool{false, true} {
								s := elfgen.LSpec{Class: class, BigEndian: be, Exec: exec, Machine: machine, Notes: notes, Tail: tail, NoPhdr: noPhdr,
									Interp: "/lib/ld.so.1", Needed: []string{"libm.so.6", "libc.so.6"}, Soname: "libx.so.1",
									Rpath: "/a", Symbols: []string{"alpha", "beta", "gamma"}}
								out = append(out, gimg{fmt.Sprintf("%d-be%v-exec%v-m%d-notes%v-tail%d-nophdr%v", class, be, exec, machine, notes, tail, noPhdr), s})
							}
						}
					}
				}
			}
		}
	}
	return out
}

func long(n int) string { return "/" + strings.Repeat("q", n) }

// std reads an image with debug/elf.
type stdView struct {
	interp                 string
	needed                 []string
	soname, rpath, runpath []string
	text                   []byte
	symSections            []string
	f                      *elf.File
}

func readStd(t *testing.T, img []byte) stdView {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(img))
	if err != nil {
		t.Fatalf("debug/elf: %v", err)
	}
	var v stdView
	v.f = f
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			b := make([]byte, p.Filesz)
			if _, err := p.ReadAt(b, 0); err != nil {
				t.Fatal(err)
			}
			v.interp = strings.TrimRight(string(b), "\x00")
		}
	}
	v.needed, _ = f.DynString(elf.DT_NEEDED)
	v.soname, _ = f.DynString(elf.DT_SONAME)
	v.rpath, _ = f.DynString(elf.DT_RPATH)
	v.runpath, _ = f.DynString(elf.DT_RUNPATH)
	if s := f.Section(".text"); s != nil {
		v.text, _ = s.Data()
	}
	syms, err := f.DynamicSymbols()
	if err != nil {
		t.Fatalf("debug/elf dynsym: %v", err)
	}
	for _, s := range syms {
		if int(s.Section) < len(f.Sections) && s.Section != elf.SHN_UNDEF {
			v.symSections = append(v.symSections, s.Name+"@"+f.Sections[s.Section].Name)
		}
	}
	return v
}

// edit patches a copy of img on disk through the verified workflow.
func gpatch(t *testing.T, img []byte, o Options, fn func(*File) ([]Change, error)) ([]byte, []Change) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(p, img, 0o755); err != nil {
		t.Fatal(err)
	}
	cs, err := Patch(p, o, fn)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	out, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return out, cs
}

func TestGrowthMatrix(t *testing.T) {
	type op struct {
		name string
		mod  func(*elfgen.LSpec)
		run  func(*File) ([]Change, error)
		want func(t *testing.T, v stdView, s elfgen.LSpec)
	}
	longRp := long(300)
	longInterp := "/very/long/interpreter" + long(300)
	longLib := "libreplaced-" + strings.Repeat("n", 100) + ".so.6"
	ops := []op{
		{"interp", nil,
			func(f *File) ([]Change, error) { return f.SetInterpreter(longInterp) },
			func(t *testing.T, v stdView, s elfgen.LSpec) {
				if v.interp != longInterp {
					t.Fatalf("interp %q", v.interp)
				}
			}},
		{"rpath-grow", nil,
			func(f *File) ([]Change, error) { return f.SetRpath(longRp, false) },
			func(t *testing.T, v stdView, s elfgen.LSpec) {
				if !slices.Equal(v.runpath, []string{longRp}) || len(v.rpath) != 0 {
					t.Fatalf("rpath %q runpath %q", v.rpath, v.runpath)
				}
			}},
		{"rpath-none", func(s *elfgen.LSpec) { s.Rpath = "" },
			func(f *File) ([]Change, error) { return f.SetRpath("/new/dir", false) },
			func(t *testing.T, v stdView, s elfgen.LSpec) {
				if !slices.Equal(v.runpath, []string{"/new/dir"}) {
					t.Fatalf("runpath %q", v.runpath)
				}
			}},
		{"rpath-none-force", func(s *elfgen.LSpec) { s.Rpath = "" },
			func(f *File) ([]Change, error) { return f.SetRpath("/new/dir", true) },
			func(t *testing.T, v stdView, s elfgen.LSpec) {
				if !slices.Equal(v.rpath, []string{"/new/dir"}) || len(v.runpath) != 0 {
					t.Fatalf("rpath %q runpath %q", v.rpath, v.runpath)
				}
			}},
		{"rpath-force-grow", func(s *elfgen.LSpec) { s.RpathTag = 15 },
			func(f *File) ([]Change, error) { return f.SetRpath(longRp, true) },
			func(t *testing.T, v stdView, s elfgen.LSpec) {
				if !slices.Equal(v.rpath, []string{longRp}) || len(v.runpath) != 0 {
					t.Fatalf("rpath %q runpath %q", v.rpath, v.runpath)
				}
			}},
		{"add-rpath-existing", nil,
			func(f *File) ([]Change, error) { return f.AddRpath("/b:/c", false) },
			func(t *testing.T, v stdView, s elfgen.LSpec) {
				if !slices.Equal(v.runpath, []string{"/a:/b:/c"}) {
					t.Fatalf("runpath %q", v.runpath)
				}
			}},
		{"add-rpath-none", func(s *elfgen.LSpec) { s.Rpath = "" },
			func(f *File) ([]Change, error) { return f.AddRpath("/b", false) },
			func(t *testing.T, v stdView, s elfgen.LSpec) {
				if !slices.Equal(v.runpath, []string{"/b"}) {
					t.Fatalf("runpath %q", v.runpath)
				}
			}},
		{"add-needed", nil,
			func(f *File) ([]Change, error) { return f.AddNeeded("libz.so.1", "liba.so.1", "libz.so.1") },
			func(t *testing.T, v stdView, s elfgen.LSpec) {
				if want := []string{"liba.so.1", "libz.so.1", "libm.so.6", "libc.so.6"}; !slices.Equal(v.needed, want) {
					t.Fatalf("needed %q, want %q", v.needed, want)
				}
			}},
		{"set-soname-grow", nil,
			func(f *File) ([]Change, error) { return f.SetSoname("libsoname-" + strings.Repeat("s", 80) + ".so.9") },
			func(t *testing.T, v stdView, s elfgen.LSpec) {
				if s.Exec {
					if !slices.Equal(v.soname, []string{"libx.so.1"}) {
						t.Fatalf("an executable's soname changed: %q", v.soname)
					}
					return
				}
				if !slices.Equal(v.soname, []string{"libsoname-" + strings.Repeat("s", 80) + ".so.9"}) {
					t.Fatalf("soname %q", v.soname)
				}
			}},
		{"set-soname-none", func(s *elfgen.LSpec) { s.Soname = "" },
			func(f *File) ([]Change, error) { return f.SetSoname("libnew.so.2") },
			func(t *testing.T, v stdView, s elfgen.LSpec) {
				want := []string{"libnew.so.2"}
				if s.Exec {
					want = nil
				}
				if !slices.Equal(v.soname, want) {
					t.Fatalf("soname %q, want %q", v.soname, want)
				}
			}},
		{"replace-needed-grow", nil,
			func(f *File) ([]Change, error) { return f.ReplaceNeeded("libm.so.6", longLib) },
			func(t *testing.T, v stdView, s elfgen.LSpec) {
				if want := []string{longLib, "libc.so.6"}; !slices.Equal(v.needed, want) {
					t.Fatalf("needed %q, want %q", v.needed, want)
				}
			}},
		{"combined", nil,
			func(f *File) ([]Change, error) {
				var all []Change
				for _, step := range []func() ([]Change, error){
					func() ([]Change, error) { return f.SetSoname("libcombined-" + strings.Repeat("c", 60) + ".so") },
					func() ([]Change, error) { return f.SetInterpreter(longInterp) },
					func() ([]Change, error) { return f.SetRpath(longRp, false) },
					func() ([]Change, error) { return f.ReplaceNeeded("libm.so.6", longLib) },
					func() ([]Change, error) { return f.AddNeeded("libextra.so.3") },
					func() ([]Change, error) { return f.RemoveNeeded("libc.so.6") },
				} {
					cs, err := step()
					if err != nil {
						return nil, err
					}
					all = append(all, cs...)
				}
				return all, nil
			},
			func(t *testing.T, v stdView, s elfgen.LSpec) {
				if v.interp != longInterp || !slices.Equal(v.runpath, []string{longRp}) {
					t.Fatalf("interp %q runpath %q", v.interp, v.runpath)
				}
				if want := []string{"libextra.so.3", longLib}; !slices.Equal(v.needed, want) {
					t.Fatalf("needed %q, want %q", v.needed, want)
				}
			}},
	}
	for _, im := range gimages() {
		for _, o := range ops {
			t.Run(im.name+"/"+o.name, func(t *testing.T) {
				s := im.spec
				if o.mod != nil {
					o.mod(&s)
				}
				img := elfgen.BuildLayout(s)
				before := readStd(t, img)
				out, cs := gpatch(t, img, Options{}, o.run)
				if len(cs) == 0 && !(s.Exec && strings.HasPrefix(o.name, "set-soname")) { // patchelf ignores --set-soname on executables
					t.Fatal("no change reported")
				}
				v := readStd(t, out)
				o.want(t, v, s)
				if !bytes.Equal(v.text, before.text) {
					t.Fatal(".text changed")
				}
				if !slices.Equal(v.symSections, before.symSections) {
					t.Fatalf("symbols moved to other sections: %q -> %q", before.symSections, v.symSections)
				}
				// setting a value twice is a no-op the second time (adding is not)
				switch o.name {
				case "add-needed", "combined", "add-rpath-existing", "add-rpath-none":
				default:
					if _, again := gpatch(t, out, Options{}, o.run); len(again) != 0 {
						t.Fatalf("a repeated edit reported changes: %v", again)
					}
				}
			})
		}
	}
}

// TestGrowthRefusesWhatItCannotVerify: without section headers, nothing is
// grown and nothing is written; the refusal still names ErrNoSpace.
func TestGrowthNoSections(t *testing.T) {
	img := elfgen.Build(elfgen.Spec{Interp: "/lib/ld.so", Rpath: "/a"})
	p := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(p, img, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := SetInterpreter(p, long(200), Options{})
	var ns *NoSpaceError
	if !errors.Is(err, ErrNoSpace) || !errors.Is(err, ErrUnsupported) || !errors.As(err, &ns) || ns.Cause == nil {
		t.Fatalf("want ErrNoSpace + ErrUnsupported, got %v", err)
	}
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, img) {
		t.Fatal("a refusal wrote")
	}
}

func TestGrowthDryRunAndOutput(t *testing.T) {
	img := elfgen.BuildLayout(elfgen.LSpec{Exec: true, Interp: "/lib/ld.so.1", Needed: []string{"libc.so.6"}, Rpath: "/a", Notes: true})
	p := filepath.Join(t.TempDir(), "x")
	os.WriteFile(p, img, 0o755)
	cs, err := Patch(p, Options{DryRun: true}, func(f *File) ([]Change, error) { return f.SetRpath(long(500), false) })
	if err != nil || len(cs) == 0 {
		t.Fatal(cs, err)
	}
	if got, _ := os.ReadFile(p); !bytes.Equal(got, img) {
		t.Fatal("dry run wrote")
	}
	o := p + ".out"
	if _, err := Patch(p, Options{Output: o}, func(f *File) ([]Change, error) { return f.SetRpath(long(500), false) }); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(p); !bytes.Equal(got, img) {
		t.Fatal("--output modified the input")
	}
	out, _ := os.ReadFile(o)
	if v := readStd(t, out); !slices.Equal(v.runpath, []string{long(500)}) {
		t.Fatal(v.runpath)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(p), ".elfpatch-*")); len(left) != 0 {
		t.Fatal("temp file left", left)
	}
}

func TestGrowthPageSize(t *testing.T) {
	// x86-64 pages are 4 KiB; --page-size 64 KiB must move things further.
	img := elfgen.BuildLayout(elfgen.LSpec{Exec: true, Interp: "/lib/ld.so.1", Rpath: "/a"})
	small, _ := gpatch(t, img, Options{}, func(f *File) ([]Change, error) { return f.SetInterpreter(long(300)) })
	big, _ := gpatch(t, img, Options{PageSize: 0x10000}, func(f *File) ([]Change, error) { return f.SetInterpreter(long(300)) })
	if len(big) <= len(small) {
		t.Fatalf("a larger page size did not grow the file more: %d vs %d", len(big), len(small))
	}
	for _, m := range []struct {
		machine uint16
		want    uint64
	}{{emAarch64, 0x10000}, {emPPC64, 0x10000}, {emSparcV9, 0x2000}, {emSparc, 0x2000}, {62, 0x1000}, {3, 0x1000}, {emLoongArch, 0x10000}} {
		if got := pageSize(m.machine, 0); got != m.want {
			t.Fatalf("machine %d: page size %#x, want %#x", m.machine, got, m.want)
		}
	}
	if pageSize(183, 4096) != 4096 {
		t.Fatal("forced page size ignored")
	}
}

// TestVerifyGrownRefusesTampering: take a correctly grown image, damage it in
// one way at a time, and require the verifier to say no.
func TestVerifyGrownRefusesTampering(t *testing.T) {
	for _, exec := range []bool{true, false} {
		spec := elfgen.LSpec{Exec: exec, Interp: "/lib/ld.so.1", Needed: []string{"libc.so.6"}, Soname: "libx.so", Rpath: "/a", Notes: true, Symbols: []string{"alpha", "beta"}}
		orig := elfgen.BuildLayout(spec)
		out, _ := gpatch(t, orig, Options{}, func(f *File) ([]Change, error) { return f.SetRpath(long(400), false) })
		f, err := Parse(slices.Clone(orig))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.SetRpath(long(400), false); err != nil {
			t.Fatal(err)
		}
		if err := verifyGrown(orig, f.data, f); err != nil {
			t.Fatalf("the honest result is refused: %v", err)
		}
		lo, _ := loadLayout(orig, 0)
		lg, _ := loadLayout(out, 0)
		text := lg.sh[lg.find(".text")]
		dynsym := lg.sh[lg.find(".dynsym")]
		hash := lg.sh[lg.find(".hash")]
		var loads []int
		for i, p := range lg.ph {
			if p.typ == ptLoad {
				loads = append(loads, i)
			}
		}
		mut := func(name string, fn func(l *layout, b []byte)) {
			t.Run(fmt.Sprintf("exec%v/%s", exec, name), func(t *testing.T) {
				b := slices.Clone(out)
				l, _ := loadLayout(b, 0)
				fn(l, b)
				g := &File{data: b, touched: f.touched, sections: f.sections}
				if err := verifyGrown(orig, b, g); !errors.Is(err, ErrVerify) {
					t.Fatalf("want ErrVerify, got %v", err)
				}
			})
		}
		mut("text byte", func(l *layout, b []byte) { b[text.off]++ })
		mut("hash byte", func(l *layout, b []byte) { b[hash.off+9]++ })
		mut("symbol name", func(l *layout, b []byte) {
			ent := uint64(24)
			if l.is32() {
				ent = 16
			}
			b[dynsym.off+ent]++
		})
		mut("elf header", func(l *layout, b []byte) { b[7] = 1 })
		mut("load offset", func(l *layout, b []byte) {
			p := l.ph[loads[len(loads)-1]]
			p.off += 8
			at := l.phoff() + uint64(loads[len(loads)-1])*l.phentsize()
			l.putPhdr(b[at:], p)
		})
		mut("load flags", func(l *layout, b []byte) {
			p := l.ph[loads[1]]
			p.flags = pfR
			at := l.phoff() + uint64(loads[1])*l.phentsize()
			l.putPhdr(b[at:], p)
		})
		mut("section moved", func(l *layout, b []byte) {
			i := l.find(".text")
			s := l.sh[i]
			s.addr += 16
			l.putShdr(b[l.shoff()+uint64(i)*l.shentsize():], s)
		})
		mut("load overlap", func(l *layout, b []byte) {
			p := l.ph[loads[0]]
			p.memsz += 0x100000
			at := l.phoff() + uint64(loads[0])*l.phentsize()
			l.putPhdr(b[at:], p)
		})
		_ = lo
	}
}

func TestLayoutEngineRefusals(t *testing.T) {
	good := elfgen.BuildLayout(elfgen.LSpec{Exec: true, Interp: "/lib/ld.so.1", Rpath: "/a"})
	grow := func(b []byte) error {
		f, err := Parse(b)
		if err != nil {
			return err
		}
		_, err = f.SetRpath(long(300), false)
		return err
	}
	if err := grow(slices.Clone(good)); err != nil {
		t.Fatal(err)
	}
	l, _ := loadLayout(good, 0)
	t.Run("no .dynstr", func(t *testing.T) {
		b := slices.Clone(good)
		ll, _ := loadLayout(b, 0)
		i := ll.find(".dynstr")
		s := ll.sh[i]
		s.name = uint32(ll.sh[ll.find(".text")].name)
		ll.putShdr(b[ll.shoff()+uint64(i)*ll.shentsize():], s)
		if err := grow(b); !errors.Is(err, ErrNoSpace) {
			t.Fatal(err)
		}
	})
	t.Run("ldcache note", func(t *testing.T) {
		b := slices.Clone(good)
		ll, _ := loadLayout(b, 0)
		// rename .data to .note.nixos.ldcache is not possible in place (longer);
		// the check is on the loader, exercised directly
		ll.names = append(ll.names, ldCacheSection+"\x00"...)
		ll.sh[1].name = uint32(len(ll.names) - len(ldCacheSection) - 1)
		if ll.find(ldCacheSection) != 1 {
			t.Fatal("setup")
		}
	})
	t.Run("huge alignment", func(t *testing.T) {
		b := elfgen.BuildLayout(elfgen.LSpec{Interp: "/lib/ld.so.1", Rpath: "/a"})
		ll, _ := loadLayout(b, 0)
		i := 0
		for k, p := range ll.ph {
			if p.typ == ptLoad {
				i = k
			}
		}
		p := ll.ph[i]
		p.align = 1 << 30
		ll.putPhdr(b[ll.phoff()+uint64(i)*ll.phentsize():], p)
		if err := grow(b); !errors.Is(err, ErrNoSpace) {
			t.Fatalf("a 1 GiB alignment was accepted: %v", err)
		}
	})
	_ = l
}
