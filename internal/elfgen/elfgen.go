// Package elfgen builds tiny synthetic ELF images (headers, PT_INTERP,
// PT_DYNAMIC, .dynstr, optional .dynsym+DT_HASH) in every class/endianness
// combination, for tests, fuzz seeds and the committed fixture corpus. The
// files are not runnable; real, runnable ELFs are built in CI by gcc.
package elfgen

import "encoding/binary"

// Spec describes one image.
type Spec struct {
	Class     int // 32 or 64 (default 64)
	BigEndian bool
	Machine   uint16

	Interp     string
	InterpSlot int // bytes reserved incl. NUL (default len+1)

	Needed []string
	Soname string

	Rpath     string
	RpathSlot int   // bytes reserved EXCLUDING the NUL (default len)
	RpathTag  int64 // 29 (RUNPATH, default) or 15 (RPATH)

	// TailNeeded adds a DT_NEEDED whose string is the last n bytes of the
	// rpath string (a merged tail), n > 0.
	TailNeeded int
	// Symbols adds a .dynsym (+DT_HASH) whose names are the given strings;
	// TailSymbol makes the first symbol name the last n bytes of the rpath.
	Symbols    []string
	TailSymbol int

	FreeDyn int // trailing DT_NULL entries (default 3)
}

const base = 0x400000

// Build returns the image.
func Build(s Spec) []byte {
	if s.Class == 0 {
		s.Class = 64
	}
	var o binary.ByteOrder = binary.LittleEndian
	if s.BigEndian {
		o = binary.BigEndian
	}
	if s.Machine == 0 {
		s.Machine = 62
		if s.Class == 32 {
			s.Machine = 3
		}
	}
	if s.RpathTag == 0 {
		s.RpathTag = 29
	}
	if s.FreeDyn == 0 {
		s.FreeDyn = 3
	}
	w, ehdr, phent, dynent, symEnt := 8, 64, 56, 16, 24
	if s.Class == 32 {
		w, ehdr, phent, dynent, symEnt = 4, 52, 32, 8, 16
	}
	nph := 2
	if s.Interp != "" {
		nph = 3
	}
	put := func(b []byte, v uint64) {
		if w == 4 {
			o.PutUint32(b, uint32(v))
		} else {
			o.PutUint64(b, v)
		}
	}
	align := func(n int) int { return (n + 7) &^ 7 }

	// .dynstr
	str := []byte{0}
	add := func(x string, slot int) int {
		off := len(str)
		str = append(str, x...)
		for len(str)-off < slot {
			str = append(str, 0)
		}
		str = append(str, 0)
		return off
	}
	var neededOff []int
	for _, n := range s.Needed {
		neededOff = append(neededOff, add(n, 0))
	}
	sonameOff := -1
	if s.Soname != "" {
		sonameOff = add(s.Soname, 0)
	}
	rpathOff := -1
	if s.Rpath != "" || s.RpathSlot > 0 {
		slot := s.RpathSlot
		if slot < len(s.Rpath) {
			slot = len(s.Rpath)
		}
		rpathOff = add(s.Rpath, slot)
	}
	tailOff := -1
	if s.TailNeeded > 0 && rpathOff >= 0 {
		tailOff = rpathOff + len(s.Rpath) - s.TailNeeded
	}
	var symOffs []int
	for i, n := range s.Symbols {
		if i == 0 && s.TailSymbol > 0 && rpathOff >= 0 {
			symOffs = append(symOffs, rpathOff+len(s.Rpath)-s.TailSymbol)
			continue
		}
		symOffs = append(symOffs, add(n, 0))
	}

	// layout
	phEnd := ehdr + nph*phent
	interpOff := align(phEnd)
	interpLen := 0
	if s.Interp != "" {
		interpLen = len(s.Interp) + 1
		if s.InterpSlot > interpLen {
			interpLen = s.InterpSlot
		}
	}
	strOff := align(interpOff + interpLen)
	symOff, hashOff, symEnd := 0, 0, strOff+len(str)
	nsym := 0
	if len(s.Symbols) > 0 {
		nsym = 1 + len(s.Symbols)
		symOff = align(strOff + len(str))
		hashOff = align(symOff + nsym*symEnt)
		symEnd = hashOff + 4*(3+nsym)
	}
	dynOff := align(symEnd)

	type ent struct{ tag, val uint64 }
	var dyn []ent
	for _, off := range neededOff {
		dyn = append(dyn, ent{1, uint64(off)})
	}
	if tailOff >= 0 {
		dyn = append(dyn, ent{1, uint64(tailOff)})
	}
	if sonameOff >= 0 {
		dyn = append(dyn, ent{14, uint64(sonameOff)})
	}
	if rpathOff >= 0 {
		dyn = append(dyn, ent{uint64(s.RpathTag), uint64(rpathOff)})
	}
	dyn = append(dyn, ent{5, base + uint64(strOff)}, ent{10, uint64(len(str))})
	if nsym > 0 {
		dyn = append(dyn, ent{6, base + uint64(symOff)}, ent{4, base + uint64(hashOff)}, ent{11, uint64(symEnt)})
	}
	dynLen := (len(dyn) + s.FreeDyn) * dynent
	total := dynOff + dynLen
	b := make([]byte, total)

	// ELF header
	copy(b, "\x7fELF")
	b[4] = byte(s.Class / 32)
	b[5] = 1
	if s.BigEndian {
		b[5] = 2
	}
	b[6] = 1
	o.PutUint16(b[16:], 3) // ET_DYN
	o.PutUint16(b[18:], s.Machine)
	o.PutUint32(b[20:], 1)
	if s.Class == 32 {
		o.PutUint32(b[28:], uint32(ehdr)) // phoff
		o.PutUint16(b[40:], uint16(ehdr))
		o.PutUint16(b[42:], uint16(phent))
		o.PutUint16(b[44:], uint16(nph))
		o.PutUint16(b[46:], 40)
	} else {
		o.PutUint64(b[32:], uint64(ehdr))
		o.PutUint16(b[52:], uint16(ehdr))
		o.PutUint16(b[54:], uint16(phent))
		o.PutUint16(b[56:], uint16(nph))
		o.PutUint16(b[58:], 64)
	}

	ph := func(i int, typ uint32, off, size int, flags uint32) {
		p := b[ehdr+i*phent:]
		o.PutUint32(p, typ)
		if s.Class == 32 {
			o.PutUint32(p[4:], uint32(off))
			o.PutUint32(p[8:], uint32(base+off))
			o.PutUint32(p[12:], uint32(base+off))
			o.PutUint32(p[16:], uint32(size))
			o.PutUint32(p[20:], uint32(size))
			o.PutUint32(p[24:], flags)
			o.PutUint32(p[28:], 8)
		} else {
			o.PutUint32(p[4:], flags)
			o.PutUint64(p[8:], uint64(off))
			o.PutUint64(p[16:], uint64(base+off))
			o.PutUint64(p[24:], uint64(base+off))
			o.PutUint64(p[32:], uint64(size))
			o.PutUint64(p[40:], uint64(size))
			o.PutUint64(p[48:], 8)
		}
	}
	i := 0
	ph(i, 1, 0, total, 7)
	i++
	if s.Interp != "" {
		ph(i, 3, interpOff, interpLen, 4)
		i++
		copy(b[interpOff:], s.Interp)
	}
	ph(i, 2, dynOff, dynLen, 6)
	copy(b[strOff:], str)
	if nsym > 0 {
		for k, off := range symOffs {
			o.PutUint32(b[symOff+(k+1)*symEnt:], uint32(off))
		}
		o.PutUint32(b[hashOff:], 1)
		o.PutUint32(b[hashOff+4:], uint32(nsym))
	}
	for k, e := range dyn {
		put(b[dynOff+k*dynent:], e.tag)
		put(b[dynOff+k*dynent+w:], e.val)
	}
	return b
}
