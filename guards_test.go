package elfpatch

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/go-binfmt/elfpatch/internal/elfgen"
)

func wantMsg(t *testing.T, err error, is error, msg string) {
	t.Helper()
	if err == nil || (is != nil && !errors.Is(err, is)) || !strings.Contains(err.Error(), msg) {
		t.Fatalf("got %v, want %v containing %q", err, is, msg)
	}
}

// Each refusal of verify is told apart by what it says, not only by its class:
// a check that is removed must change a message here, not slip through behind
// a neighbour that happens to refuse the same input.
func TestVerifyEachRefusal(t *testing.T) {
	orig := elfgen.Build(spec(variants[0]))
	f := mustParse(t, slices.Clone(orig))
	if _, err := f.SetRpath("/q", false); err != nil {
		t.Fatal(err)
	}
	first := f.merged()[0]
	last := f.merged()[len(f.merged())-1]
	if err := verify(orig, f.data, f); err != nil {
		t.Fatal(err)
	}
	out := slices.Clone(f.data)

	wantMsg(t, verify(orig, out[:len(out)-1], f), ErrVerify, "length changed")

	gap := slices.Clone(out) // before the first declared range
	gap[first.off-1] ^= 1
	wantMsg(t, verify(orig, gap, f), ErrVerify, "near offset")

	tail := slices.Clone(out) // after the last declared range
	tail[len(tail)-1] ^= 1
	if last.end >= uint64(len(tail)) {
		t.Fatal("fixture has no bytes after the last range")
	}
	wantMsg(t, verify(orig, tail, f), ErrVerify, "after offset")

	wrong := slices.Clone(out) // inside a range, but not what the editor wrote
	wrong[first.off] ^= 1
	wantMsg(t, verify(orig, wrong, f), ErrVerify, "differ from the intended")

	wantMsg(t, verify(make([]byte, len(orig)), out, f), ErrNotELF, "")
	wantMsg(t, verify(orig, make([]byte, len(orig)), f), ErrVerify, "does not parse")

	// An input whose untouched fields cannot be read is not an input we can judge.
	bad := slices.Clone(orig)
	g := mustParse(t, bad)
	i, _ := g.firstDyn(dtNeeded)
	binary.LittleEndian.PutUint64(bad[g.dyn[i].off+8:], 1<<30)
	h := mustParse(t, slices.Clone(bad))
	h.SetRpath("/q", false)
	err := verify(bad, h.data, h)
	wantMsg(t, err, ErrCorrupt, "outside .dynstr")
	if errors.Is(err, ErrVerify) {
		t.Fatal("an unreadable input is not a verification failure")
	}

	// An output whose field cannot be read is: the edit damaged it.
	k := mustParse(t, slices.Clone(orig))
	ent := k.dyn[i]
	broken := slices.Clone(k.data)
	binary.LittleEndian.PutUint64(broken[ent.off+8:], 1<<30)
	k.data = broken
	k.allowed = []rng{{ent.off, ent.off + 16}}
	wantMsg(t, verify(orig, broken, k), ErrVerify, "outside .dynstr")
}

func TestSetRpathGuards(t *testing.T) {
	orig := elfgen.Build(spec(variants[0]))
	f := mustParse(t, slices.Clone(orig))
	_, err := f.SetRpath("a\x00b", false)
	wantMsg(t, err, nil, "invalid rpath")
	if errors.Is(err, ErrVerify) {
		t.Fatal("NUL must be refused up front, not found by read-back")
	}

	// Same value, same tag: nothing is written at all.
	cs, err := f.SetRpath(spec(variants[0]).Rpath, false)
	if err != nil || cs != nil || len(f.allowed) != 0 {
		t.Fatalf("no-op wrote: %v %v %v", cs, err, f.allowed)
	}

	// Same value but a DT_RPATH tag: only the tag changes.
	s := spec(variants[0])
	s.RpathTag = dtRpath
	g := mustParse(t, elfgen.Build(s))
	cs, err = g.SetRpath(s.Rpath, false)
	if err != nil || len(cs) != 1 || cs[0].Field != "tag" {
		t.Fatalf("%v %v", cs, err)
	}
	cs, err = g.SetRpath(s.Rpath, true) // and forcing it back
	if err != nil || len(cs) != 1 || cs[0].Field != "tag" {
		t.Fatalf("%v %v", cs, err)
	}
	if _, ok, _ := g.Rpath(); !ok {
		t.Fatal("DT_RPATH not restored")
	}

	// An unreadable current value is reported, not overwritten.
	bad := slices.Clone(orig)
	b := mustParse(t, slices.Clone(bad))
	i, _ := b.firstDyn(dtRunpath)
	binary.LittleEndian.PutUint64(bad[b.dyn[i].off+8:], 1<<30)
	c := mustParse(t, bad)
	if _, err := c.SetRpath("/x", false); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	if _, err := c.RemoveRpath(); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
}

func TestShrinkReportsUnreadableNeeded(t *testing.T) {
	bad := elfgen.Build(spec(variants[0]))
	g := mustParse(t, slices.Clone(bad))
	i, _ := g.firstDyn(dtNeeded)
	binary.LittleEndian.PutUint64(bad[g.dyn[i].off+8:], 1<<30)
	if _, err := mustParse(t, bad).ShrinkRpath("/"); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
}

func TestNoOpDoesNotRewrite(t *testing.T) {
	p := write(t, elfgen.Build(spec(variants[0])))
	before, _ := os.Stat(p)
	for _, edit := range []func() ([]Change, error){
		func() ([]Change, error) { return RemoveNeeded(p, "libnothere.so", Options{}) },
		func() ([]Change, error) { return SetInterpreter(p, "/lib64/ld-linux-x86-64.so.2", Options{}) },
		func() ([]Change, error) { return SetRpath(p, spec(variants[0]).Rpath, false, Options{}) },
	} {
		if cs, err := edit(); err != nil || cs != nil {
			t.Fatal(cs, err)
		}
	}
	after, _ := os.Stat(p)
	if !os.SameFile(before, after) {
		t.Fatal("a no-op replaced the file")
	}
	ents, _ := os.ReadDir(filepath.Dir(p))
	if len(ents) != 1 {
		t.Fatalf("temp file left behind: %v", ents)
	}
}

func TestCloseIsSafe(t *testing.T) {
	if err := mustParse(t, elfgen.Build(spec(variants[0]))).Close(); err != nil {
		t.Fatal(err)
	}
	f, err := Open(write(t, elfgen.Build(spec(variants[0]))))
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := f.Needed(); len(n) != 3 {
		t.Fatal(n)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal("second Close:", err)
	}
	if f.data != nil {
		t.Fatal("data still reachable after Close")
	}
}

func TestOpenRefusals(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, nil, 0o644)
	if _, err := Open(empty); !errors.Is(err, ErrNotELF) {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("directory")
	}
	if _, err := Open(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing")
	}
	txt := write(t, []byte("0123456789abcdef0123456789abcdef"))
	if f, err := Open(txt); !errors.Is(err, ErrNotELF) || f != nil {
		t.Fatal(f, err)
	}
}
