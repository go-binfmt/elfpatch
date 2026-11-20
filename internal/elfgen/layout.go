package elfgen

import "encoding/binary"

// LSpec describes an image WITH section headers and the three-segment layout a
// linker produces (read-only headers and dynamic tables, executable text,
// writable .dynamic), which phase 2 needs: growing is decided by the sections.
// Like Build, the files are not runnable.
type LSpec struct {
	Class     int // 32 or 64 (default 64)
	BigEndian bool
	Machine   uint16 // default x86-64 / i386; 183 (aarch64) has 64 KiB pages, 2 (sparc) 8 KiB
	Exec      bool   // ET_EXEC at 0x400000 (else ET_DYN at 0)

	Interp   string
	Needed   []string
	Soname   string
	Rpath    string // "" = none
	RpathTag int64  // 29 (RUNPATH, default) or 15 (RPATH)
	Symbols  []string
	// Notes adds a .note section and its PT_NOTE.
	Notes bool
	// Verneed adds a .gnu.version_r with one entry per file name, each needing
	// one version; the names share their strings with Needed, as a linker's do.
	Verneed []string
	// Tail adds a non-allocated tail section of this many bytes after the
	// writable segment, so that the file no longer ends in it.
	Tail int
	// NoPhdr leaves out PT_PHDR.
	NoPhdr bool
	// FreeDyn is the number of spare DT_NULL entries (default 2).
	FreeDyn int
}

// BuildLayout returns the image.
func BuildLayout(s LSpec) []byte {
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
		s.FreeDyn = 2
	}
	page := 0x1000
	switch s.Machine {
	case 183, 21, 8, 20, 50, 191, 258:
		page = 0x10000
	case 2, 43:
		page = 0x2000
	}
	is32 := s.Class == 32
	w, ehdr, phent, shent, dynent, symEnt := 8, 64, 56, 64, 16, 24
	if is32 {
		w, ehdr, phent, shent, dynent, symEnt = 4, 52, 32, 40, 8, 16
	}
	base := 0
	etype := 3
	if s.Exec {
		base, etype = 0x400000, 2
	}
	put := func(b []byte, v uint64) {
		if is32 {
			o.PutUint32(b, uint32(v))
		} else {
			o.PutUint64(b, v)
		}
	}
	align := func(n, a int) int { return (n + a - 1) / a * a }

	// .dynstr
	str := []byte{0}
	seen := map[string]int{}
	add := func(x string) int {
		if off, ok := seen[x]; ok {
			return off
		}
		off := len(str)
		seen[x] = off
		str = append(str, x...)
		str = append(str, 0)
		return off
	}
	var neededOff []int
	for _, n := range s.Needed {
		neededOff = append(neededOff, add(n))
	}
	sonameOff, rpathOff := -1, -1
	if s.Soname != "" {
		sonameOff = add(s.Soname)
	}
	if s.Rpath != "" {
		rpathOff = add(s.Rpath)
	}
	var verFile []int
	verAux := -1
	for _, n := range s.Verneed {
		verFile = append(verFile, add(n))
	}
	if len(verFile) > 0 {
		verAux = add("GLIBC_2.0")
	}
	var symStr []int
	for _, n := range s.Symbols {
		symStr = append(symStr, add(n))
	}

	// section names
	names := []byte{0}
	nameOf := func(n string) int {
		off := len(names)
		names = append(names, n...)
		names = append(names, 0)
		return off
	}

	nph := 4 // LOAD x3 + DYNAMIC
	if !s.NoPhdr {
		nph++
	}
	if s.Interp != "" {
		nph++
	}
	if s.Notes {
		nph++
	}
	phEnd := ehdr + nph*phent
	cur := phEnd
	type sec struct {
		name       string
		nameOff    int
		typ        uint32
		flags      uint64
		off, size  int
		link, info uint32
		alignment  int
		entsize    int
		addr       int
		idx        int
	}
	var secs []*sec
	newSec := func(name string, typ uint32, flags uint64, size, alignment int) *sec {
		cur = align(cur, alignment)
		x := &sec{name: name, nameOff: nameOf(name), typ: typ, flags: flags, off: cur, size: size, alignment: alignment, idx: len(secs) + 1}
		cur += size
		secs = append(secs, x)
		return x
	}
	var interp, note *sec
	if s.Interp != "" {
		interp = newSec(".interp", 1, 2, len(s.Interp)+1, 1)
	}
	if s.Notes {
		note = newSec(".note.gnu.build-id", 7, 2, 36, 4)
	}
	nsym := 1 + len(s.Symbols)
	hash := newSec(".hash", 5, 2, 4*(2+1+nsym), 4)
	dynsym := newSec(".dynsym", 11, 2, nsym*symEnt, w)
	dynstr := newSec(".dynstr", 3, 2, len(str), 1)
	var vr *sec
	if len(verFile) > 0 {
		vr = newSec(".gnu.version_r", 0x6ffffffe, 2, len(verFile)*32, 4)
	}
	firstEnd := cur

	cur = align(firstEnd, page)
	text := newSec(".text", 1, 6, 0x40, 16)
	textEnd := cur

	cur = align(textEnd, page)
	nd := len(neededOff) + 5 + s.FreeDyn // + HASH STRTAB SYMTAB STRSZ SYMENT
	if vr != nil {
		nd += 2 // VERNEED VERNEEDNUM
	}
	if sonameOff >= 0 {
		nd++
	}
	if rpathOff >= 0 {
		nd++
	}
	dynLen := nd * dynent
	dynamic := newSec(".dynamic", 6, 3, dynLen, w)
	_ = newSec(".data", 1, 3, 16, 8)
	rwEnd := cur
	if s.Tail > 0 {
		_ = newSec(".comment", 1, 0, s.Tail, 1)
	}
	shstr := newSec(".shstrtab", 3, 0, 0, 1)
	// .shstrtab names itself too; sizes are known now.
	shstr.size = len(names)
	cur = shstr.off + shstr.size
	shoff := align(cur, 8)
	nsec := len(secs) + 1
	total := shoff + nsec*shent
	b := make([]byte, total)

	// addresses
	for _, x := range secs {
		if x.flags&2 != 0 {
			x.addr = base + x.off
		}
	}
	hash.link, hash.entsize = uint32(dynsym.idx), 4
	dynsym.link, dynsym.info, dynsym.entsize = uint32(dynstr.idx), 1, symEnt
	if vr != nil {
		vr.link, vr.info = uint32(dynstr.idx), uint32(len(verFile))
	}
	dynamic.link, dynamic.entsize = uint32(dynstr.idx), dynent

	// ELF header
	copy(b, "\x7fELF")
	b[4] = byte(s.Class / 32)
	b[5] = 1
	if s.BigEndian {
		b[5] = 2
	}
	b[6] = 1
	o.PutUint16(b[16:], uint16(etype))
	o.PutUint16(b[18:], s.Machine)
	o.PutUint32(b[20:], 1)
	if is32 {
		o.PutUint32(b[24:], uint32(base+text.off))
		o.PutUint32(b[28:], uint32(ehdr))
		o.PutUint32(b[32:], uint32(shoff))
		o.PutUint16(b[40:], uint16(ehdr))
		o.PutUint16(b[42:], uint16(phent))
		o.PutUint16(b[44:], uint16(nph))
		o.PutUint16(b[46:], uint16(shent))
		o.PutUint16(b[48:], uint16(nsec))
		o.PutUint16(b[50:], uint16(shstr.idx))
	} else {
		o.PutUint64(b[24:], uint64(base+text.off))
		o.PutUint64(b[32:], uint64(ehdr))
		o.PutUint64(b[40:], uint64(shoff))
		o.PutUint16(b[52:], uint16(ehdr))
		o.PutUint16(b[54:], uint16(phent))
		o.PutUint16(b[56:], uint16(nph))
		o.PutUint16(b[58:], uint16(shent))
		o.PutUint16(b[60:], uint16(nsec))
		o.PutUint16(b[62:], uint16(shstr.idx))
	}

	// program headers
	pi := 0
	ph := func(typ uint32, flags uint32, off, filesz, memsz, al int) {
		p := b[ehdr+pi*phent:]
		pi++
		v := uint64(base + off)
		o.PutUint32(p, typ)
		if is32 {
			o.PutUint32(p[4:], uint32(off))
			o.PutUint32(p[8:], uint32(v))
			o.PutUint32(p[12:], uint32(v))
			o.PutUint32(p[16:], uint32(filesz))
			o.PutUint32(p[20:], uint32(memsz))
			o.PutUint32(p[24:], flags)
			o.PutUint32(p[28:], uint32(al))
		} else {
			o.PutUint32(p[4:], flags)
			o.PutUint64(p[8:], uint64(off))
			o.PutUint64(p[16:], v)
			o.PutUint64(p[24:], v)
			o.PutUint64(p[32:], uint64(filesz))
			o.PutUint64(p[40:], uint64(memsz))
			o.PutUint64(p[48:], uint64(al))
		}
	}
	if !s.NoPhdr {
		ph(6, 4, ehdr, nph*phent, nph*phent, w)
	}
	if interp != nil {
		ph(3, 4, interp.off, interp.size, interp.size, 1)
	}
	ph(1, 4, 0, firstEnd, firstEnd, page)
	ph(1, 5, text.off, text.size, text.size, page)
	ph(1, 6, dynamic.off, rwEnd-dynamic.off, rwEnd-dynamic.off, page)
	ph(2, 6, dynamic.off, dynamic.size, dynamic.size, w)
	if note != nil {
		ph(4, 4, note.off, note.size, note.size, 4)
	}

	// contents
	if interp != nil {
		copy(b[interp.off:], s.Interp)
	}
	copy(b[dynstr.off:], str)
	hb := b[hash.off:]
	o.PutUint32(hb, 1)
	o.PutUint32(hb[4:], uint32(nsym))
	if nsym > 1 {
		o.PutUint32(hb[8:], 1) // bucket 0 -> symbol 1
		for i := 1; i < nsym; i++ {
			next := i + 1
			if next == nsym {
				next = 0
			}
			o.PutUint32(hb[12+4*i:], uint32(next))
		}
	}
	for i, off := range symStr {
		sym := b[dynsym.off+(i+1)*symEnt:]
		o.PutUint32(sym, uint32(off))
		if is32 {
			o.PutUint32(sym[4:], uint32(base+text.off))
			sym[12] = 0x12 // GLOBAL FUNC
			o.PutUint16(sym[14:], uint16(text.idx))
		} else {
			sym[4] = 0x12
			o.PutUint16(sym[6:], uint16(text.idx))
			o.PutUint64(sym[8:], uint64(base+text.off))
		}
	}
	for i := 0; i < text.size; i++ {
		b[text.off+i] = 0xc3
	}
	type ent struct{ tag, val uint64 }
	var dyn []ent
	for _, off := range neededOff {
		dyn = append(dyn, ent{1, uint64(off)})
	}
	if sonameOff >= 0 {
		dyn = append(dyn, ent{14, uint64(sonameOff)})
	}
	if rpathOff >= 0 {
		dyn = append(dyn, ent{uint64(s.RpathTag), uint64(rpathOff)})
	}
	if vr != nil {
		dyn = append(dyn, ent{0x6ffffffe, uint64(vr.addr)}, ent{0x6fffffff, uint64(len(verFile))})
	}
	dyn = append(dyn, ent{4, uint64(hash.addr)}, ent{5, uint64(dynstr.addr)}, ent{6, uint64(dynsym.addr)},
		ent{10, uint64(len(str))}, ent{11, uint64(symEnt)})
	for k, e := range dyn {
		put(b[dynamic.off+k*dynent:], e.tag)
		put(b[dynamic.off+k*dynent+w:], e.val)
	}
	for i, f := range verFile {
		v := b[vr.off+i*32:]
		o.PutUint16(v, 1)
		o.PutUint16(v[2:], 1)
		o.PutUint32(v[4:], uint32(f))
		o.PutUint32(v[8:], 16)
		if i+1 < len(verFile) {
			o.PutUint32(v[12:], 32)
		}
		o.PutUint16(v[16+6:], 2)
		o.PutUint32(v[16+8:], uint32(verAux))
	}
	copy(b[shstr.off:], names)
	if note != nil {
		n := b[note.off:]
		o.PutUint32(n, 4)      // namesz
		o.PutUint32(n[4:], 20) // descsz
		o.PutUint32(n[8:], 3)  // NT_GNU_BUILD_ID
		copy(n[12:], "GNU\x00")
		for i := 0; i < 20; i++ {
			n[16+i] = byte(i + 1)
		}
	}

	// section headers
	for _, x := range secs {
		h := b[shoff+x.idx*shent:]
		o.PutUint32(h, uint32(x.nameOff))
		o.PutUint32(h[4:], x.typ)
		if is32 {
			o.PutUint32(h[8:], uint32(x.flags))
			o.PutUint32(h[12:], uint32(x.addr))
			o.PutUint32(h[16:], uint32(x.off))
			o.PutUint32(h[20:], uint32(x.size))
			o.PutUint32(h[24:], x.link)
			o.PutUint32(h[28:], x.info)
			o.PutUint32(h[32:], uint32(x.alignment))
			o.PutUint32(h[36:], uint32(x.entsize))
		} else {
			o.PutUint64(h[8:], x.flags)
			o.PutUint64(h[16:], uint64(x.addr))
			o.PutUint64(h[24:], uint64(x.off))
			o.PutUint64(h[32:], uint64(x.size))
			o.PutUint32(h[40:], x.link)
			o.PutUint32(h[44:], x.info)
			o.PutUint64(h[48:], uint64(x.alignment))
			o.PutUint64(h[56:], uint64(x.entsize))
		}
	}
	return b
}

// GrowSeeds is the list of layout images the growth fuzz corpus is made from:
// every class and byte order, executable and shared object, three page sizes,
// with and without notes, PT_PHDR and a file tail.
func GrowSeeds() []LSpec {
	var out []LSpec
	for _, class := range []int{64, 32} {
		for _, be := range []bool{false, true} {
			for _, exec := range []bool{true, false} {
				for _, m := range []uint16{0, 183, 2} {
					out = append(out, LSpec{
						Class: class, BigEndian: be, Exec: exec, Machine: m, Notes: m == 183, Tail: int(m) * 16, NoPhdr: m == 2,
						Interp: "/lib/ld.so.1", Needed: []string{"libm.so.6", "libc.so.6"}, Soname: "libx.so.1",
						Rpath: "/a", Symbols: []string{"alpha", "beta"}, Verneed: []string{"libm.so.6"},
					})
				}
			}
		}
	}
	return out
}
