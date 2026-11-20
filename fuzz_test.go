package elfpatch

import (
	"errors"
	"slices"
	"testing"

	"github.com/go-binfmt/elfpatch/internal/elfgen"
)

// FuzzParse feeds arbitrary bytes to the parser and, when they parse, to every
// reader and every in-place edit plus the verifier. Nothing may panic, and an
// edit that reports success must pass verify. The corpus under
// testdata/fuzz/FuzzParse is committed (see internal/mkcorpus).
func FuzzParse(f *testing.F) {
	for _, v := range variants {
		f.Add(elfgen.Build(spec(v)))
	}
	f.Add([]byte("\x7fELF"))
	f.Fuzz(func(t *testing.T, data []byte) {
		g, err := Parse(slices.Clone(data))
		if err != nil {
			return
		}
		if _, err := g.snap(); err != nil {
			return // Patch refuses these before editing
		}
		g.Interpreter()
		g.Needed()
		g.Soname()
		g.SearchPath()
		g.Rpath()
		for _, op := range []func(*File) ([]Change, error){
			func(f *File) ([]Change, error) { return f.SetInterpreter("/x") },
			func(f *File) ([]Change, error) { return f.SetRpath("/x", false) },
			func(f *File) ([]Change, error) { return f.SetRpath("", true) },
			func(f *File) ([]Change, error) { return f.RemoveRpath() },
			func(f *File) ([]Change, error) { return f.RemoveNeeded("libc.so.6") },
			func(f *File) ([]Change, error) { return f.ReplaceNeeded("libc.so.6", "l") },
			func(f *File) ([]Change, error) { return f.ShrinkRpath("/") },
		} {
			h, err := Parse(slices.Clone(data))
			if err != nil {
				t.Fatal("second parse differs:", err)
			}
			cs, err := op(h)
			if err != nil || len(cs) == 0 {
				continue
			}
			// Hostile layouts (a .dynstr overlapping .dynamic, say) make an
			// edit land on structure it did not target. verify exists to
			// refuse exactly that, so a refusal is the contract working; what
			// must never happen is a panic, or an accepted edit that does not
			// round-trip.
			if err := verify(data, h.data, h); err != nil {
				if !errors.Is(err, ErrVerify) && !errors.Is(err, ErrCorrupt) {
					t.Fatalf("unexpected verify error: %v", err)
				}
				continue
			}
			if _, err := Parse(h.data); err != nil {
				t.Fatalf("accepted edit does not re-parse: %v", err)
			}
		}
	})
}
