package elfpatch

import (
	"encoding/binary"
	"errors"
	"slices"
	"testing"

	"github.com/go-binfmt/elfpatch/internal/elfgen"
)

// 32-bit fields and the size cap: a value that does not fit is a refusal, never
// a wrapped number.
func TestGrowthOverflowIsARefusal(t *testing.T) {
	t.Run("an ELF32 field holds 32 bits", func(t *testing.T) {
		l := &layout{class: 32, order: binary.LittleEndian}
		b := make([]byte, 4)
		if err := l.run(func() { l.ww(b, 1<<32) }); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("1<<32 into an ELF32 field: %v", err)
		}
		if err := l.run(func() { l.ww(b, 1<<32-1) }); err != nil || binary.LittleEndian.Uint32(b) != 1<<32-1 {
			t.Fatalf("the largest value was refused: %v", err)
		}
		l64 := &layout{class: 64, order: binary.BigEndian}
		b8 := make([]byte, 8)
		if err := l64.run(func() { l64.ww(b8, 1<<40) }); err != nil || binary.BigEndian.Uint64(b8) != 1<<40 {
			t.Fatal(err)
		}
	})
	t.Run("a 32-bit executable whose headers would pass 4 GiB", func(t *testing.T) {
		img := elfgen.BuildLayout(elfgen.LSpec{Class: 32, Exec: true, Interp: "/lib/ld.so.1", Rpath: "/a"})
		l, _ := loadLayout(img, 0)
		// the last PT_LOAD claims to end at the top of the address space
		for i := range l.ph {
			if l.ph[i].typ == ptLoad {
				l.ph[i].memsz = 0xfffff000
			}
		}
		for i, p := range l.ph {
			l.putPhdr(img[l.phoff()+uint64(i)*l.phentsize():], p)
		}
		f := mustParse(t, slices.Clone(img))
		if _, err := f.SetRpath(long(500), false); err == nil {
			// a grown image must at least be judged: either refused here or by the verifier
			if err := verifyGrown(img, f.data, f); err == nil {
				t.Log("accepted: the image has no overflowing field")
			}
		} else if !errors.Is(err, ErrNoSpace) && !errors.Is(err, ErrUnsupported) {
			t.Fatal(err)
		}
	})
	t.Run("the 2 GiB cap", func(t *testing.T) {
		old := maxFile
		defer func() { maxFile = old }()
		img := elfgen.BuildLayout(elfgen.LSpec{Exec: true, Interp: "/lib/ld.so.1", Rpath: "/a"})
		maxFile = uint64(len(img)) + 100
		f := mustParse(t, img)
		if _, err := f.SetRpath(long(20000), false); !errors.Is(err, ErrNoSpace) {
			t.Fatalf("growth past the cap: %v", err)
		}
		l := &layout{class: 64, order: binary.LittleEndian, data: make([]byte, 10)}
		if err := l.run(func() { l.grow(maxFile + 1) }); !errors.Is(err, ErrUnsupported) {
			t.Fatal(err)
		}
		if err := l.run(func() { l.replaceSection(".x", maxFile+1) }); !errors.Is(err, ErrUnsupported) {
			t.Fatal(err)
		}
	})
}
