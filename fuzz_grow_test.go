package elfpatch

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/go-binfmt/elfpatch/internal/elfgen"
)

// FuzzGrow feeds arbitrary bytes to the growth paths: the layout engine, the
// edits that use it, and the structural verifier. Whatever the bytes are:
//
//   - nothing panics (a hostile header is a refusal, never a crash);
//   - an edit that grows and reports success produces an image that re-parses,
//     is within the size cap, and that verifyGrown accepts or refuses with
//     ErrVerify (a refusal is the contract working: a hostile layout can make
//     the engine produce something it must not write);
//   - the input is never modified by an edit that returned an error through
//     Patch (checked by the workflow tests; here Parse works on a copy).
//
// The corpus under testdata/fuzz/FuzzGrow is committed (see internal/mkcorpus):
// every class and byte order, executable and shared object, with and without
// notes, PT_PHDR and a file tail, and 32-bit/page-size edge cases.
func FuzzGrow(f *testing.F) {
	for _, s := range elfgen.GrowSeeds() {
		f.Add(elfgen.BuildLayout(s))
	}
	f.Add([]byte("\x7fELF"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := Parse(slices.Clone(data)); err != nil {
			return
		}
		long := "/" + strings.Repeat("q", 700)
		for _, page := range []uint64{0, 1 << 31} {
			for i, op := range []func(*File) ([]Change, error){
				func(f *File) ([]Change, error) { return f.SetInterpreter(long) },
				func(f *File) ([]Change, error) { return f.SetRpath(long, false) },
				func(f *File) ([]Change, error) { return f.SetRpath(long, true) },
				func(f *File) ([]Change, error) { return f.AddRpath("/b", false) },
				func(f *File) ([]Change, error) { return f.AddNeeded("libz.so.1", "liba.so.1") },
				func(f *File) ([]Change, error) { return f.SetSoname(long) },
				func(f *File) ([]Change, error) { return f.ReplaceNeeded("libc.so.6", long) },
				func(f *File) ([]Change, error) { return f.ReplaceNeeded("libm.so.6", "libm.so.7") },
			} {
				h, err := Parse(slices.Clone(data))
				if err != nil {
					t.Fatal("second parse differs:", err)
				}
				if _, err := h.snap(); err != nil {
					return // Patch refuses these before editing
				}
				h.forcedPage = page
				cs, err := op(h)
				if err != nil || len(cs) == 0 || !h.grown {
					continue
				}
				if uint64(len(h.data)) > maxFile {
					t.Fatalf("op %d: grown image of %d bytes is over the cap", i, len(h.data))
				}
				if _, err := Parse(h.data); err != nil {
					t.Fatalf("op %d: grown image does not re-parse: %v", i, err)
				}
				if err := verifyGrown(data, h.data, h); err != nil && !errors.Is(err, ErrVerify) && !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrUnsupported) {
					t.Fatalf("op %d: unexpected verify error: %v", i, err)
				}
			}
		}
	})
}
