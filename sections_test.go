package elfpatch

import (
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

const (
	secTab = 0x100 // where the section header table sits
	secStr = 0x300 // where the string table sits
)

// mkSections builds a bare-metal ELF of 0x400 bytes whose section header table
// holds secs; names are written into a string table at secStr. Fields go in at
// the offsets the ELF specification gives, not through the parser under test.
// The last section is the string table.
func mkSections(class int, o binary.ByteOrder, secs []Section, names []string) []byte {
	b := mkProgs(class, o, 40, 0, nil, 0x400)
	str := []byte{0}
	nameOff := make([]uint32, len(secs))
	for i, n := range names {
		if i == 0 {
			continue
		}
		nameOff[i] = uint32(len(str))
		str = append(str, n...)
		str = append(str, 0)
	}
	copy(b[secStr:], str)
	ent := 40
	if class == 64 {
		ent = 64
		o.PutUint64(b[40:], secTab)
		o.PutUint16(b[58:], 64)
		o.PutUint16(b[60:], uint16(len(secs)))
		o.PutUint16(b[62:], uint16(len(secs)-1))
	} else {
		o.PutUint32(b[32:], secTab)
		o.PutUint16(b[46:], 40)
		o.PutUint16(b[48:], uint16(len(secs)))
		o.PutUint16(b[50:], uint16(len(secs)-1))
	}
	for i, s := range secs {
		h := b[secTab+ent*i:]
		o.PutUint32(h, nameOff[i])
		o.PutUint32(h[4:], s.Type)
		if class == 64 {
			o.PutUint64(h[8:], s.Flags)
			o.PutUint64(h[16:], s.Addr)
			o.PutUint64(h[24:], s.Off)
			o.PutUint64(h[32:], s.Size)
		} else {
			o.PutUint32(h[8:], uint32(s.Flags))
			o.PutUint32(h[12:], uint32(s.Addr))
			o.PutUint32(h[16:], uint32(s.Off))
			o.PutUint32(h[20:], uint32(s.Size))
		}
	}
	return b
}

func goodSections() ([]Section, []string) {
	secs := []Section{
		{},
		{Type: 1, Flags: 6, Addr: 0x8000_0000, Off: 0x200, Size: 8},
		{Type: 8, Flags: 3, Addr: 0x8000_0008, Off: 0x208, Size: 0x1_0000_0000}, // NOBITS: size is not in the file
		{Type: 3, Off: secStr, Size: 0x40},
	}
	return secs, []string{"", ".text", ".bss", ".shstrtab"}
}

func TestSectionsAllLayouts(t *testing.T) {
	secs, names := goodSections()
	for _, class := range []int{32, 64} {
		for _, o := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			want := append([]Section(nil), secs...)
			for i := range want {
				want[i].Name = names[i]
			}
			if class == 32 { // fields are 32 bits wide
				want[2].Size &= 0xffff_ffff
			}
			img := mkSections(class, o, secs, names)
			f, err := Parse(img)
			if err != nil {
				t.Fatalf("class %d %v: %v", class, o, err)
			}
			got, err := f.Sections()
			if err != nil {
				t.Fatalf("class %d %v: %v", class, o, err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("class %d %v:\n got %+v\nwant %+v", class, o, got, want)
			}
		}
	}
}

// callSections calls Sections and reports a panic as a failed assertion: a
// refusal is an error value, never a crash.
func callSections(t *testing.T, what string, f *File) (got []Section, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: Sections panicked: %v", what, r)
		}
	}()
	return f.Sections()
}

func TestSectionsAbsent(t *testing.T) {
	for _, class := range []int{32, 64} {
		f, err := Parse(mkProgs(class, binary.LittleEndian, 40, 0, nil, 0x100))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := callSections(t, "absent", f); got != nil || !errors.Is(err, ErrUnsupported) {
			t.Errorf("class %d: %v, %v; want nil and ErrUnsupported", class, got, err)
		}
	}
}

func TestSectionsRefusals(t *testing.T) {
	le := binary.LittleEndian
	tests := []struct {
		name   string
		is     error
		mutate func(secs []Section, names []string, b []byte) []byte
	}{
		{"extended count", ErrUnsupported, func(_ []Section, _ []string, b []byte) []byte { le.PutUint16(b[60:], 0); return b }},
		{"extended string index", ErrCorrupt, func(_ []Section, _ []string, b []byte) []byte { le.PutUint16(b[62:], 0xffff); return b }},
		{"entry size", ErrCorrupt, func(_ []Section, _ []string, b []byte) []byte { le.PutUint16(b[58:], 63); return b }},
		{"table outside", ErrCorrupt, func(_ []Section, _ []string, b []byte) []byte { le.PutUint64(b[40:], 0x3e0); return b }},
		{"table wraps", ErrCorrupt, func(_ []Section, _ []string, b []byte) []byte { le.PutUint64(b[40:], ^uint64(0)-8); return b }},
		{"string index", ErrCorrupt, func(_ []Section, _ []string, b []byte) []byte { le.PutUint16(b[62:], 4); return b }},
		{"data outside", ErrCorrupt, func(s []Section, n []string, _ []byte) []byte {
			s[1].Off, s[1].Size = 0x200, 0x201 // ends one byte past the 0x400-byte image
			return mkSections(64, le, s, n)
		}},
		{"data wraps", ErrCorrupt, func(s []Section, n []string, _ []byte) []byte {
			s[1].Off, s[1].Size = ^uint64(0)-1, 4
			return mkSections(64, le, s, n)
		}},
		{"string table is NOBITS", ErrCorrupt, func(s []Section, n []string, _ []byte) []byte {
			s[3].Type = 8
			return mkSections(64, le, s, n)
		}},
		{"name outside", ErrCorrupt, func(s []Section, n []string, b []byte) []byte {
			s[3].Size = 4
			b = mkSections(64, le, s, n)
			le.PutUint32(b[secTab+64:], 4) // section 1's name offset = table size
			return b
		}},
		{"name unterminated", ErrCorrupt, func(s []Section, n []string, b []byte) []byte {
			s[3].Size = 4 // ".te" fits, its NUL does not
			return mkSections(64, le, s, n)
		}},
	}
	for _, tc := range tests {
		secs, names := goodSections()
		secs[2].Size = 0
		img := tc.mutate(secs, names, mkSections(64, le, secs, names))
		f, err := Parse(img)
		if err != nil {
			t.Fatalf("%s: Parse refused it first: %v", tc.name, err)
		}
		got, err := callSections(t, tc.name, f)
		if !errors.Is(err, tc.is) || got != nil {
			t.Errorf("%s: %v, %v; want nil and %v", tc.name, got, err, tc.is)
		}
	}
}

// FuzzSections: whatever Parse accepts, Sections never panics, and every
// section that has bytes in the file lies inside it.
func FuzzSections(f *testing.F) {
	secs, names := goodSections()
	secs[2].Size = 0
	for _, class := range []int{32, 64} {
		f.Add(mkSections(class, binary.LittleEndian, secs, names))
		f.Add(mkSections(class, binary.BigEndian, secs, names))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		file, err := Parse(data)
		if err != nil {
			return
		}
		got, err := file.Sections()
		if err != nil {
			return
		}
		for i, s := range got {
			if s.Type != 0 && s.Type != 8 && !inRange(s.Off, s.Size, uint64(len(data))) {
				t.Fatalf("section %d [%d,+%d) outside %d bytes", i, s.Off, s.Size, len(data))
			}
		}
	})
}
