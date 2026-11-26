package elfpatch

// Section is a read-only copy of one section header.
type Section struct {
	Name  string // from the section-name string table
	Type  uint32 // sh_type, e.g. 1 for SHT_PROGBITS, 8 for SHT_NOBITS
	Flags uint64 // sh_flags, e.g. 2 for SHF_ALLOC
	Addr  uint64 // sh_addr: the virtual address
	Off   uint64 // sh_offset
	Size  uint64 // sh_size
}

// shtNull is SHT_NULL, the reserved section 0.
const shtNull = 0

// Sections returns a copy of the section header table in file order,
// including the reserved section 0. It reads the table with the decoder the
// growing edits use, so it keeps that decoder's rules: an executable or shared
// object, and an image without section headers is refused with ErrUnsupported
// (a stripped binary has none). Beyond them every section other than SHT_NULL
// and SHT_NOBITS is checked to lie inside the image without overflowing
// (ErrCorrupt). It is lazy: Parse accepts the same images as before.
func (f *File) Sections() ([]Section, error) {
	l, err := loadLayout(f.data, 0)
	if err != nil {
		return nil, err
	}
	n := uint64(len(f.data))
	out := make([]Section, len(l.sh))
	for i, s := range l.sh {
		if s.typ != shtNull && s.typ != shtNobits && !inRange(s.off, s.size, n) {
			return nil, corrupt("section %d: [%d,+%d) outside file of %d bytes", i, s.off, s.size, n)
		}
		out[i] = Section{Name: l.secName(i), Type: s.typ, Flags: s.flags, Addr: s.addr, Off: s.off, Size: s.size}
	}
	return out, nil
}
