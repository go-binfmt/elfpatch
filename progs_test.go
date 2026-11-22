package elfpatch

import (
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

// mkProgs hand-builds a bare-metal ET_EXEC (no PT_DYNAMIC, no PT_INTERP) of
// the given class and byte order with the given program headers, padded to
// size bytes. Fields are written at the offsets the ELF specification gives,
// not through the parser under test.
func mkProgs(class int, o binary.ByteOrder, machine uint16, entry uint64, progs []Prog, size int) []byte {
	b := make([]byte, size)
	copy(b, "\x7fELF")
	b[4] = byte(class / 32)
	if o == binary.BigEndian {
		b[5] = 2
	} else {
		b[5] = 1
	}
	b[6] = 1
	o.PutUint16(b[16:], 2)
	o.PutUint16(b[18:], machine)
	if class == 32 {
		o.PutUint32(b[24:], uint32(entry))
		o.PutUint32(b[28:], 52)
		o.PutUint16(b[42:], 32)
		o.PutUint16(b[44:], uint16(len(progs)))
		for i, p := range progs {
			h := b[52+32*i:]
			o.PutUint32(h, p.Type)
			o.PutUint32(h[4:], uint32(p.Off))
			o.PutUint32(h[8:], uint32(p.Vaddr))
			o.PutUint32(h[12:], uint32(p.Paddr))
			o.PutUint32(h[16:], uint32(p.Filesz))
			o.PutUint32(h[20:], uint32(p.Memsz))
		}
		return b
	}
	o.PutUint64(b[24:], entry)
	o.PutUint64(b[32:], 64)
	o.PutUint16(b[54:], 56)
	o.PutUint16(b[56:], uint16(len(progs)))
	for i, p := range progs {
		h := b[64+56*i:]
		o.PutUint32(h, p.Type)
		o.PutUint64(h[8:], p.Off)
		o.PutUint64(h[16:], p.Vaddr)
		o.PutUint64(h[24:], p.Paddr)
		o.PutUint64(h[32:], p.Filesz)
		o.PutUint64(h[40:], p.Memsz)
	}
	return b
}

func TestProgsAndEntryAllLayouts(t *testing.T) {
	want := []Prog{
		{Type: 1, Off: 0x100, Vaddr: 0x8000_1000, Paddr: 0x8000_0000, Filesz: 0x20, Memsz: 0x40},
		{Type: 4, Off: 0xe0, Vaddr: 0x11, Paddr: 0x22, Filesz: 0, Memsz: 0x33},
	}
	for _, class := range []int{32, 64} {
		for _, o := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			img := mkProgs(class, o, 183, 0x8000_1004, want, 0x200)
			f, err := Parse(img)
			if err != nil {
				t.Fatalf("class %d %v: %v", class, o, err)
			}
			if got := f.Progs(); !reflect.DeepEqual(got, want) {
				t.Errorf("class %d %v: Progs %+v, want %+v", class, o, got, want)
			}
			if f.Entry != 0x8000_1004 || f.Machine != 183 {
				t.Errorf("class %d %v: Entry %#x Machine %d", class, o, f.Entry, f.Machine)
			}
		}
	}
}

func TestEntryKeepsHigh64Bits(t *testing.T) {
	img := mkProgs(64, binary.LittleEndian, 62, 0xffffffff80001000, nil, 0x100)
	f, err := Parse(img)
	if err != nil {
		t.Fatal(err)
	}
	if f.Entry != 0xffffffff80001000 {
		t.Errorf("Entry %#x", f.Entry)
	}
	if len(f.Progs()) != 0 {
		t.Errorf("Progs of a file with none: %v", f.Progs())
	}
}

func TestProgsIsACopy(t *testing.T) {
	img := mkProgs(64, binary.LittleEndian, 62, 0, []Prog{{Type: 1, Off: 0x100, Filesz: 4, Memsz: 4}}, 0x200)
	f, err := Parse(img)
	if err != nil {
		t.Fatal(err)
	}
	f.Progs()[0].Filesz = 99
	if f.Progs()[0].Filesz != 4 {
		t.Error("changing the returned slice changed the file")
	}
}

// FuzzProgs: whatever Parse accepts, every segment with file content lies
// inside the image, and the accessor never panics.
func FuzzProgs(f *testing.F) {
	seed := []Prog{{Type: 1, Off: 0x100, Vaddr: 1, Paddr: 2, Filesz: 0x20, Memsz: 0x40}}
	for _, class := range []int{32, 64} {
		f.Add(mkProgs(class, binary.LittleEndian, 40, 0x1000, seed, 0x200))
		f.Add(mkProgs(class, binary.BigEndian, 8, 0x1000, seed, 0x200))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		file, err := Parse(data)
		if err != nil {
			return
		}
		for i, p := range file.Progs() {
			if p.Filesz > 0 && !inRange(p.Off, p.Filesz, uint64(len(data))) {
				t.Fatalf("segment %d [%d,+%d) outside %d bytes", i, p.Off, p.Filesz, len(data))
			}
		}
	})
}

func TestProgsRefusesSegmentOutsideFile(t *testing.T) {
	// A non-LOAD segment is checked too: Progs never hands out a range that
	// lies outside the image.
	img := mkProgs(32, binary.BigEndian, 40, 0, []Prog{{Type: 4, Off: 0x1f0, Filesz: 0x20}}, 0x200)
	_, err := Parse(img)
	if !errors.Is(err, ErrCorrupt) || !errors.Is(err, ErrSegmentRange) {
		t.Errorf("err %v, want ErrCorrupt and ErrSegmentRange", err)
	}
	// Other corruption is not a segment-range error.
	short := mkProgs(32, binary.BigEndian, 40, 0, []Prog{{Type: 1, Off: 0x100, Filesz: 4}}, 0x200)
	short[6] = 9 // EI_VERSION
	if _, err := Parse(short); errors.Is(err, ErrSegmentRange) {
		t.Errorf("EI_VERSION error reported as ErrSegmentRange: %v", err)
	}
}
