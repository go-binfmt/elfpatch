package elfpatch

// Phase 2: the layout engine. It is a port of the section-replacement half of
// NixOS patchelf 0.19.3 (src/patchelf.cc): replaceSection, writeReplacedSections,
// rewriteSectionsLibrary, rewriteSectionsExecutable, shiftFile,
// trimLoadSegments, normalizeNoteSegments, rewriteHeaders and the program and
// section header sorts. Function names follow patchelf's so the two can be read
// side by side; where a line of patchelf is an assert, this code returns an
// error instead of aborting, and every value written into an ELF32 field is
// checked against 32 bits instead of wrapping.

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"math"
	"slices"
)

const (
	ptNote         = 4
	ptPhdr         = 6
	ptGnuProperty  = 0x6474e553
	ptMipsAbiflags = 0x70000003

	shtProgbits = 1
	shtSymtab   = 2
	shtRela     = 4
	shtDynamic  = 6
	shtNote     = 7
	shtNobits   = 8
	shtRel      = 9
	shtDynsym   = 11

	pfX = 1
	pfW = 2
	pfR = 4

	shfWrite = 1

	etExec = 2
	etDyn  = 3

	dtRela          = 7
	dtRel           = 17
	dtJmprel        = 23
	dtInitArray     = 25
	dtFiniArray     = 26
	dtPreinitArray  = 32
	dtVersym        = 0x6ffffff0
	dtMipsRldMapRel = 0x70000035
	dtMipsXhash     = 0x70000036

	// maxSegmentAlignment bounds the p_align honoured when placing a new
	// segment (patchelf: maxSegmentAlignment).
	maxSegmentAlignment = 0x1000000

	ldCacheSection = ".note.nixos.ldcache"
)

// Machine numbers whose ABI page size differs from 4 KiB (patchelf.cc:382-406,
// itself taken from GNU gold's abi_pagesize).
const (
	emSparc     = 2
	emPPC       = 20
	emPPC64     = 21
	emMips      = 8
	emAlpha     = 0x9026
	emIA64      = 50
	emSparcV9   = 43
	emAarch64   = 183
	emTileGX    = 191
	emLoongArch = 258
)

// pageSize is patchelf's ElfFile::getPageSize.
func pageSize(machine uint16, forced uint64) uint64 {
	if forced > 0 {
		return forced
	}
	switch machine {
	case emAlpha, emIA64, emMips, emPPC, emPPC64, emAarch64, emTileGX, emLoongArch:
		return 0x10000
	case emSparc, emSparcV9:
		return 0x2000
	}
	return 0x1000
}

type phdr struct {
	typ, flags                       uint32
	off, vaddr, paddr, filesz, memsz uint64
	align                            uint64
}

type shdr struct {
	name, typ  uint32
	flags      uint64
	addr, off  uint64
	size       uint64
	link, info uint32
	addralign  uint64
	entsize    uint64
	id         int // the index this section had when the layout was loaded
}

// layoutError is the panic payload of fail/bad; run turns it into an error.
type layoutError struct{ err error }

// layout is a mutable view of an ELF image: the byte image plus decoded copies
// of the program and section header tables, as patchelf's ElfFile holds them.
type layout struct {
	class   int
	order   binary.ByteOrder
	machine uint16
	etype   uint16
	data    []byte
	ph      []phdr
	sh      []shdr
	names   []byte // .shstrtab
	basis   []int  // basis[i]: the id of the section symbol tables mean by index i
	repl    map[string][]byte
	forced  uint64 // --page-size
}

func (l *layout) fail(format string, a ...any) {
	panic(layoutError{fmt.Errorf("%w: %s", ErrUnsupported, fmt.Sprintf(format, a...))})
}

func (l *layout) bad(format string, a ...any) {
	panic(layoutError{corrupt(format, a...)})
}

func (l *layout) run(fn func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if le, ok := r.(layoutError); ok {
				err = le.err
				return
			}
			panic(r)
		}
	}()
	fn()
	return nil
}

func (l *layout) page() uint64 { return pageSize(l.machine, l.forced) }

func (l *layout) is32() bool { return l.class == 32 }

func (l *layout) ehsize() uint64 {
	if l.is32() {
		return 52
	}
	return 64
}

func (l *layout) phentsize() uint64 {
	if l.is32() {
		return 32
	}
	return 56
}

func (l *layout) shentsize() uint64 {
	if l.is32() {
		return 40
	}
	return 64
}

// word is the width of Elf_Off/Elf_Addr/Elf_Xword-sized fields: also
// patchelf's sectionAlignment.
func (l *layout) word() uint64 {
	if l.is32() {
		return 4
	}
	return 8
}

func (l *layout) rw(b []byte) uint64 {
	if l.is32() {
		return uint64(l.order.Uint32(b))
	}
	return l.order.Uint64(b)
}

func (l *layout) ww(b []byte, v uint64) {
	if l.is32() {
		if v > math.MaxUint32 {
			l.fail("value %#x does not fit an ELF32 field", v)
		}
		l.order.PutUint32(b, uint32(v))
		return
	}
	l.order.PutUint64(b, v)
}

// Offsets of the header fields that move.
func (l *layout) atPhoff() int {
	if l.is32() {
		return 28
	}
	return 32
}

func (l *layout) atShoff() int {
	if l.is32() {
		return 32
	}
	return 40
}

func (l *layout) atPhnum() int {
	if l.is32() {
		return 44
	}
	return 56
}

func (l *layout) atShnum() int {
	if l.is32() {
		return 48
	}
	return 60
}

func (l *layout) atShstrndx() int {
	if l.is32() {
		return 50
	}
	return 62
}

func (l *layout) phoff() uint64     { return l.rw(l.data[l.atPhoff():]) }
func (l *layout) shoff() uint64     { return l.rw(l.data[l.atShoff():]) }
func (l *layout) setPhoff(v uint64) { l.ww(l.data[l.atPhoff():], v) }
func (l *layout) setShoff(v uint64) { l.ww(l.data[l.atShoff():], v) }
func (l *layout) shstrndx() int     { return int(l.order.Uint16(l.data[l.atShstrndx():])) }
func (l *layout) setShstrndx(i int) { l.order.PutUint16(l.data[l.atShstrndx():], uint16(i)) }

func (l *layout) setPhnum(n int) {
	if n > 0xfffe {
		l.fail("too many program headers (%d)", n)
	}
	l.order.PutUint16(l.data[l.atPhnum():], uint16(n))
}

func (l *layout) getPhdr(b []byte) phdr {
	o := l.order
	if l.is32() {
		return phdr{
			typ: o.Uint32(b), off: uint64(o.Uint32(b[4:])), vaddr: uint64(o.Uint32(b[8:])), paddr: uint64(o.Uint32(b[12:])),
			filesz: uint64(o.Uint32(b[16:])), memsz: uint64(o.Uint32(b[20:])), flags: o.Uint32(b[24:]), align: uint64(o.Uint32(b[28:])),
		}
	}
	return phdr{
		typ: o.Uint32(b), flags: o.Uint32(b[4:]), off: o.Uint64(b[8:]), vaddr: o.Uint64(b[16:]), paddr: o.Uint64(b[24:]),
		filesz: o.Uint64(b[32:]), memsz: o.Uint64(b[40:]), align: o.Uint64(b[48:]),
	}
}

func (l *layout) putPhdr(b []byte, p phdr) {
	o := l.order
	o.PutUint32(b, p.typ)
	if l.is32() {
		l.ww(b[4:], p.off)
		l.ww(b[8:], p.vaddr)
		l.ww(b[12:], p.paddr)
		l.ww(b[16:], p.filesz)
		l.ww(b[20:], p.memsz)
		o.PutUint32(b[24:], p.flags)
		l.ww(b[28:], p.align)
		return
	}
	o.PutUint32(b[4:], p.flags)
	o.PutUint64(b[8:], p.off)
	o.PutUint64(b[16:], p.vaddr)
	o.PutUint64(b[24:], p.paddr)
	o.PutUint64(b[32:], p.filesz)
	o.PutUint64(b[40:], p.memsz)
	o.PutUint64(b[48:], p.align)
}

func (l *layout) getShdr(b []byte) shdr {
	o := l.order
	if l.is32() {
		return shdr{
			name: o.Uint32(b), typ: o.Uint32(b[4:]), flags: uint64(o.Uint32(b[8:])), addr: uint64(o.Uint32(b[12:])),
			off: uint64(o.Uint32(b[16:])), size: uint64(o.Uint32(b[20:])), link: o.Uint32(b[24:]), info: o.Uint32(b[28:]),
			addralign: uint64(o.Uint32(b[32:])), entsize: uint64(o.Uint32(b[36:])),
		}
	}
	return shdr{
		name: o.Uint32(b), typ: o.Uint32(b[4:]), flags: o.Uint64(b[8:]), addr: o.Uint64(b[16:]),
		off: o.Uint64(b[24:]), size: o.Uint64(b[32:]), link: o.Uint32(b[40:]), info: o.Uint32(b[44:]),
		addralign: o.Uint64(b[48:]), entsize: o.Uint64(b[56:]),
	}
}

func (l *layout) putShdr(b []byte, s shdr) {
	o := l.order
	o.PutUint32(b, s.name)
	o.PutUint32(b[4:], s.typ)
	if l.is32() {
		l.ww(b[8:], s.flags)
		l.ww(b[12:], s.addr)
		l.ww(b[16:], s.off)
		l.ww(b[20:], s.size)
		o.PutUint32(b[24:], s.link)
		o.PutUint32(b[28:], s.info)
		l.ww(b[32:], s.addralign)
		l.ww(b[36:], s.entsize)
		return
	}
	o.PutUint64(b[8:], s.flags)
	o.PutUint64(b[16:], s.addr)
	o.PutUint64(b[24:], s.off)
	o.PutUint64(b[32:], s.size)
	o.PutUint32(b[40:], s.link)
	o.PutUint32(b[44:], s.info)
	o.PutUint64(b[48:], s.addralign)
	o.PutUint64(b[56:], s.entsize)
}

// loadLayout decodes the headers of an ELF image the way patchelf's ElfFile
// constructor does, with its refusals: executables and shared objects only,
// and section headers are required.
func loadLayout(data []byte, forcedPage uint64) (*layout, error) {
	f, err := Parse(data)
	if err != nil {
		return nil, err
	}
	l := &layout{class: f.Class, order: f.Order, machine: f.Machine, etype: f.Type, data: data, repl: map[string][]byte{}, forced: forcedPage}
	err = l.run(func() { l.load() })
	if err != nil {
		return nil, err
	}
	return l, nil
}

func (l *layout) load() {
	n := uint64(len(l.data))
	if l.etype != etExec && l.etype != etDyn {
		l.fail("wrong ELF type %d", l.etype)
	}
	phnum := uint64(l.order.Uint16(l.data[l.atPhnum():]))
	shnum := uint64(l.order.Uint16(l.data[l.atShnum():]))
	phentsize := uint64(l.order.Uint16(l.data[l.atPhnum()-2:]))
	shentsize := uint64(l.order.Uint16(l.data[l.atShnum()-2:]))
	if !inRange(l.phoff(), phnum*phentsize, n) {
		l.bad("program header table out of bounds")
	}
	if shnum == 0 {
		l.fail("no section headers: growing needs them (a stripped or self-decompressing binary cannot be grown)")
	}
	if !inRange(l.shoff(), shnum*shentsize, n) {
		l.bad("section header table out of bounds")
	}
	if phentsize != l.phentsize() {
		l.bad("program headers have wrong size")
	}
	if shentsize != l.shentsize() {
		l.bad("section headers have wrong size")
	}
	for i := uint64(0); i < phnum; i++ {
		at := l.phoff() + i*phentsize
		l.ph = append(l.ph, l.getPhdr(l.data[at:at+phentsize]))
	}
	for i := uint64(0); i < shnum; i++ {
		at := l.shoff() + i*shentsize
		s := l.getShdr(l.data[at : at+shentsize])
		s.id = int(i)
		l.sh = append(l.sh, s)
	}
	idx := l.shstrndx()
	if idx >= len(l.sh) {
		l.bad("string table index out of bounds")
	}
	st := l.sh[idx]
	if st.typ == shtNobits || !inRange(st.off, st.size, n) {
		l.bad("string table out of bounds")
	}
	if st.size == 0 {
		l.bad("string table size is zero")
	}
	l.names = slices.Clone(l.data[st.off : st.off+st.size])
	if l.names[len(l.names)-1] != 0 {
		l.bad("string table is not zero terminated")
	}
	for i := range l.sh {
		if uint64(l.sh[i].name) >= uint64(len(l.names)) {
			l.bad("section name offset out of bounds")
		}
		if int(l.sh[i].link) >= len(l.sh) {
			l.bad("sh_link of section %d out of bounds", i)
		}
		if t := l.sh[i].typ; (t == shtRel || t == shtRela) && int(l.sh[i].info) >= len(l.sh) {
			l.bad("sh_info of section %d out of bounds", i)
		}
		l.basis = append(l.basis, i)
	}
	if l.find(ldCacheSection) >= 0 {
		l.fail("the file carries a %s note (patchelf --build-resolution-cache); growing it is not supported", ldCacheSection)
	}
}

func (l *layout) secName(i int) string {
	o := l.sh[i].name
	b := l.names[o:]
	for j, c := range b {
		if c == 0 {
			return string(b[:j])
		}
	}
	return ""
}

// find returns the index of the first section called name, or -1.
func (l *layout) find(name string) int {
	for i := 1; i < len(l.sh); i++ {
		if l.secName(i) == name {
			return i
		}
	}
	return -1
}

func (l *layout) must(name string) int {
	i := l.find(name)
	if i < 0 {
		extra := ""
		if name == ".interp" || name == ".dynamic" || name == ".dynstr" {
			extra = ". The input file is most likely statically linked"
		}
		l.fail("cannot find section '%s'%s", name, extra)
	}
	return i
}

func (l *layout) secBytes(s shdr) []byte {
	if s.typ == shtNobits || !inRange(s.off, s.size, uint64(len(l.data))) {
		l.bad("section data [%d,+%d) outside the file", s.off, s.size)
	}
	return l.data[s.off : s.off+s.size]
}

// replaceSection starts (or resizes) the replacement of section name, keeping
// what it already holds, and returns the new content. size is bounded by the
// 2 GiB cap before anything is allocated.
func (l *layout) replaceSection(name string, size uint64) []byte {
	if size > maxFile {
		l.fail("section %s would be %d bytes, over the %d-byte limit", name, size, maxFile)
	}
	old, ok := l.repl[name]
	if !ok {
		s := l.sh[l.must(name)]
		if s.typ == shtNobits {
			l.fail("section %s has no file contents to move", name)
		}
		old = l.secBytes(s)
	}
	s := make([]byte, size)
	copy(s, old)
	l.repl[name] = s
	return s
}

func (l *layout) canReplaceSection(i int) bool {
	return l.secName(i) == ".interp" || l.sh[i].typ != shtProgbits
}

func roundUp(n, m uint64) uint64 {
	if n == 0 {
		return m
	}
	return ((n-1)/m + 1) * m
}

// grow resizes the image to n bytes, zero-filling.
func (l *layout) grow(n uint64) {
	if n > maxFile {
		l.fail("the result would be %d bytes, over the %d-byte limit", n, maxFile)
	}
	if n <= uint64(len(l.data)) {
		l.data = l.data[:n]
		return
	}
	d := make([]byte, n)
	copy(d, l.data)
	l.data = d
}

func (l *layout) checkOff(off, size uint64) {
	if !inRange(off, size, uint64(len(l.data))) {
		l.bad("data offset extends past file end")
	}
}

// sortPhdrs: the PHDR first, then everything by p_paddr, stable.
func (l *layout) sortPhdrs() {
	less := func(x, y phdr) bool {
		if y.typ == ptPhdr {
			return false
		}
		if x.typ == ptPhdr {
			return true
		}
		return x.paddr < y.paddr
	}
	slices.SortStableFunc(l.ph, func(x, y phdr) int {
		switch {
		case less(x, y):
			return -1
		case less(y, x):
			return 1
		}
		return 0
	})
}

// sortShdrs sorts sections 1.. by file offset and renumbers sh_link, sh_info of
// relocation sections and e_shstrndx. patchelf does this by section NAME,
// which breaks when two sections share one; this follows the permutation.
func (l *layout) sortShdrs() {
	n := len(l.sh)
	order := make([]int, 0, n-1)
	for i := 1; i < n; i++ {
		order = append(order, i)
	}
	slices.SortStableFunc(order, func(a, b int) int { return cmp.Compare(l.sh[a].off, l.sh[b].off) })
	pos := make([]int, n)
	out := make([]shdr, n)
	out[0] = l.sh[0]
	for k, old := range order {
		out[k+1] = l.sh[old]
		pos[old] = k + 1
	}
	for i := 1; i < n; i++ {
		s := &out[i]
		if s.link != 0 {
			s.link = uint32(pos[s.link])
		}
		if s.info != 0 && (s.typ == shtRel || s.typ == shtRela) {
			s.info = uint32(pos[s.info])
		}
	}
	if k := l.shstrndx(); k > 0 && k < n {
		l.setShstrndx(pos[k])
	}
	l.sh = out
}

// shiftFile moves the whole file after startOffset by extraPages pages
// (patchelf shiftFile), so that the headers and the relocated sections can
// grow at the front without moving any virtual address after them.
func (l *layout) shiftFile(extraPages, startOffset, extraBytes uint64) {
	if startOffset < l.ehsize() || startOffset >= uint64(len(l.data)) {
		l.fail("section offsets are inconsistent with file size")
	}
	shift := extraPages * l.page()
	oldSize := uint64(len(l.data))
	if shift > maxFile || oldSize+shift > maxFile {
		l.fail("the result would exceed the %d-byte limit", maxFile)
	}
	d := make([]byte, oldSize+shift)
	copy(d, l.data[:startOffset])
	copy(d[startOffset+shift:], l.data[startOffset:])
	l.data = d

	l.setPhoff(l.ehsize())
	if l.shoff() >= startOffset {
		l.setShoff(l.shoff() + shift)
	}
	for i := 1; i < len(l.sh); i++ {
		if l.sh[i].off >= startOffset {
			l.sh[i].off += shift
		}
	}

	split := -1
	var splitShift uint64
	for i := range l.ph {
		p := &l.ph[i]
		start := p.off
		if start < startOffset && start+p.filesz > startOffset && p.typ == ptLoad {
			if split != -1 {
				l.fail("two PT_LOAD segments cross offset %#x", startOffset)
			}
			split = i
			splitShift = startOffset - start
			p.off = startOffset
			p.memsz -= min(p.memsz, splitShift)
			p.filesz -= splitShift
			p.paddr += splitShift
			p.vaddr += splitShift
			start = startOffset
		}
		if start >= startOffset {
			p.off = start + shift
			if p.align != 0 && (p.vaddr-p.off)%p.align != 0 {
				p.align = l.page()
			}
		} else {
			if p.paddr >= shift {
				p.paddr -= shift
			}
			if p.vaddr >= shift {
				p.vaddr -= shift
			}
		}
	}
	if split == -1 {
		return
	}
	s := l.ph[split]
	l.ph = append(l.ph, phdr{
		typ: ptLoad, flags: pfR | pfW, align: l.page(),
		off:    s.off - splitShift - shift,
		paddr:  s.paddr - splitShift - shift,
		vaddr:  s.vaddr - splitShift - shift,
		filesz: splitShift + extraBytes,
		memsz:  splitShift + extraBytes,
	})
	l.setPhnum(len(l.ph))
}

func (l *layout) syncSeg(typ uint32, s shdr) {
	for i := range l.ph {
		if l.ph[i].typ == typ {
			l.ph[i].off, l.ph[i].vaddr, l.ph[i].paddr = s.off, s.addr, s.addr
			l.ph[i].filesz, l.ph[i].memsz = s.size, s.size
		}
	}
}

func (l *layout) writeReplacedSections(curOff, startAddr, startOffset uint64) {
	// Overwrite the old contents with 'Z' first (patchelf's clobberOldSections),
	// so a section that moves over its own old place is not clobbered after it
	// was written.
	for name := range l.repl {
		s := l.sh[l.must(name)]
		if s.typ != shtNobits {
			l.checkOff(s.off, s.size)
			clear(l.data[s.off : s.off+s.size])
			for j := s.off; j < s.off+s.size; j++ {
				l.data[j] = 'Z'
			}
		}
	}
	noted := map[int]bool{}
	for i := range l.sh {
		s := &l.sh[i]
		name := l.secName(i)
		content, ok := l.repl[name]
		if !ok {
			continue
		}
		orig := *s
		l.checkOff(curOff, uint64(len(content)))
		copy(l.data[curOff:], content)
		s.off = curOff
		s.addr = startAddr + (curOff - startOffset)
		s.size = uint64(len(content))
		s.addralign = l.word()

		switch name {
		case ".interp":
			l.syncSeg(ptInterp, *s)
		case ".dynamic":
			l.syncSeg(ptDynamic, *s)
		}
		if s.typ == shtNote {
			if orig.addralign < l.word() {
				s.addralign = orig.addralign
			}
			for j := range l.ph {
				p := &l.ph[j]
				if p.typ != ptNote || noted[j] {
					continue
				}
				pStart, pEnd := p.off, p.off+p.filesz
				sStart, sEnd := orig.off, orig.off+orig.size
				if !(sStart >= pStart && sStart < pEnd) && !(sEnd > pStart && sEnd <= pEnd) {
					continue
				}
				if pStart != sStart || pEnd != sEnd {
					l.fail("unsupported overlap of SHT_NOTE and PT_NOTE")
				}
				p.off, p.vaddr, p.paddr, p.filesz, p.memsz = s.off, s.addr, s.addr, s.size, s.size
				noted[j] = true
			}
		}
		if name == ".MIPS.abiflags" {
			l.syncSeg(ptMipsAbiflags, *s)
		}
		if name == ".note.gnu.property" {
			l.syncSeg(ptGnuProperty, *s)
		}
		curOff += roundUp(uint64(len(content)), l.word())
	}
	clear(l.repl)
}

func (l *layout) rewriteSections() {
	if len(l.repl) == 0 {
		return
	}
	switch l.etype {
	case etDyn:
		l.rewriteSectionsLibrary()
	case etExec:
		l.rewriteSectionsExecutable()
	default:
		l.fail("unknown ELF type")
	}
}

func (l *layout) rewriteSectionsLibrary() {
	var startPage, firstPage uint64
	alignStartPage := l.page()
	for _, p := range l.ph {
		if end := p.vaddr + p.memsz; end > startPage {
			startPage = end
		}
		if p.typ == ptPhdr {
			firstPage = p.vaddr - p.off
		}
		alignStartPage = max(alignStartPage, p.align)
	}
	if alignStartPage > maxSegmentAlignment {
		l.fail("segment alignment is implausibly large; refusing to grow file")
	}
	startPage = roundUp(startPage, alignStartPage)

	numNotes := uint64(0)
	for _, s := range l.sh {
		if s.typ == shtNote {
			numNotes++
		}
	}
	phtSize := roundUp((uint64(len(l.ph))+numNotes+1)*l.phentsize(), l.word())
	shtSize := roundUp(uint64(len(l.sh))*l.shentsize(), l.word())

	relocatePht := false
	phtEnd := l.phoff() + phtSize
	for i := 1; i < len(l.sh); i++ {
		off := l.sh[i].off
		if off <= l.phoff() || off >= phtEnd {
			continue
		}
		if _, ok := l.repl[l.secName(i)]; !ok && !l.canReplaceSection(i) {
			relocatePht = true
			break
		}
	}
	if !relocatePht {
		for i := 1; i < len(l.sh); i++ {
			off := l.sh[i].off
			if off <= l.phoff() || off >= phtEnd {
				continue
			}
			if _, ok := l.repl[l.secName(i)]; !ok {
				l.replaceSection(l.secName(i), l.sh[i].size)
			}
		}
	}

	neededSpace := shtSize
	if relocatePht {
		neededSpace += phtSize
	}
	for _, s := range l.repl {
		neededSpace += roundUp(uint64(len(s)), l.word())
	}

	startOffset := roundUp(uint64(len(l.data)), alignStartPage)
	// One byte more than the content: binutils 2.30's readelf checks that the
	// dynamic segment is strictly smaller than the file.
	l.grow(startOffset + neededSpace + 1)

	var lastSegAddr uint64
	if n := len(l.ph); n > 0 && l.ph[n-1].typ == ptLoad && l.ph[n-1].flags == pfR|pfW && l.ph[n-1].align == alignStartPage {
		last := &l.ph[n-1]
		segEnd := roundUp(last.off+last.memsz, alignStartPage)
		// Extend only when the address continues where the new area starts;
		// patchelf assumes it, this checks it and otherwise adds a segment.
		if segEnd == startOffset && last.vaddr+(startOffset-last.off) == startPage {
			newSz := startOffset + neededSpace - last.off
			last.filesz, last.memsz = newSz, newSz
			lastSegAddr = last.vaddr + newSz - neededSpace
		}
	}
	if lastSegAddr == 0 {
		l.ph = append(l.ph, phdr{typ: ptLoad, off: startOffset, vaddr: startPage, paddr: startPage,
			filesz: neededSpace, memsz: neededSpace, flags: pfR | pfW, align: alignStartPage})
		l.setPhnum(len(l.ph))
		if startPage%alignStartPage != startOffset%alignStartPage {
			l.fail("new segment is not congruent with its file offset")
		}
		lastSegAddr = startPage
	}

	l.normalizeNoteSegments()

	curOff := startOffset
	if relocatePht {
		l.setPhoff(curOff)
		curOff += phtSize
	}
	l.setShoff(curOff)
	curOff += shtSize

	l.writeReplacedSections(curOff, startPage, startOffset)

	if relocatePht {
		l.rewriteHeaders(lastSegAddr)
	} else {
		l.rewriteHeaders(firstPage + l.phoff())
	}
}

func (l *layout) findLoadByOffset(off uint64) int {
	for i, p := range l.ph {
		if p.typ == ptLoad && p.off <= off && p.off+p.filesz > off {
			return i
		}
	}
	return -1
}

func (l *layout) trimLoadSegments(startOffset uint64, headerIndex int) {
	for i := len(l.ph); i != 0; {
		i--
		p := &l.ph[i]
		if i == headerIndex || p.typ != ptLoad || p.off >= startOffset {
			continue
		}
		skipped := startOffset - p.off
		if p.filesz <= skipped && p.memsz <= skipped {
			l.ph = slices.Delete(l.ph, i, i+1)
			continue
		}
		p.off = startOffset
		p.vaddr += skipped
		p.paddr += skipped
		if p.filesz > skipped {
			p.filesz -= skipped
		} else {
			p.filesz = 0
		}
		if p.memsz > skipped {
			p.memsz -= skipped
		} else {
			p.memsz = 0
		}
	}
	l.setPhnum(len(l.ph))
}

func (l *layout) rewriteSectionsExecutable() {
	l.sortShdrs()

	lastReplaced := 0
	for i := 1; i < len(l.sh); i++ {
		if _, ok := l.repl[l.secName(i)]; ok {
			lastReplaced = i
		}
	}
	if lastReplaced == 0 || lastReplaced+1 >= len(l.sh) {
		l.fail("the replaced sections are the last in the file: layout not supported")
	}

	// Replace every section before the last replaced one, as far as possible,
	// stopping at one that cannot move in virtual memory (PROGBITS other than
	// .interp) and, as patchelf does, right after .dynstr.
	startOffset := l.sh[lastReplaced+1].off
	startAddr := l.sh[lastReplaced+1].addr
	prev := ""
	for i := 1; i <= lastReplaced; i++ {
		s := l.sh[i]
		name := l.secName(i)
		if (s.typ == shtProgbits && name != ".interp") || prev == ".dynstr" {
			startOffset, startAddr = s.off, s.addr
			lastReplaced = i - 1
			break
		}
		if _, ok := l.repl[name]; !ok {
			l.replaceSection(name, s.size)
		}
		prev = name
	}

	page := l.page()
	if startAddr%page != startOffset%page || startAddr < startOffset {
		l.fail("first reserved section is not congruent with its page (address %#x, offset %#x)", startAddr, startOffset)
	}
	firstPage := startAddr - startOffset

	if l.shoff() < startOffset {
		// The section headers sit where the relocated sections go: move them to
		// the end of the file first.
		shoffNew := uint64(len(l.data))
		size := uint64(len(l.sh)) * l.shentsize()
		l.grow(shoffNew + size)
		l.setShoff(shoffNew)
		l.sortShdrs()
		for i := 1; i < len(l.sh); i++ {
			at := shoffNew + uint64(i)*l.shentsize()
			l.putShdr(l.data[at:at+l.shentsize()], l.sh[i])
		}
	}

	l.normalizeNoteSegments()

	reuseHeaderLoad := false
	originalHeaderBase := firstPage
	var originalHeaderFlags uint32
	if h := l.findLoadByOffset(l.ehsize()); h >= 0 {
		originalHeaderBase = l.ph[h].vaddr - l.ph[h].off
		originalHeaderFlags = l.ph[h].flags
		reuseHeaderLoad = l.ph[h].off+l.ph[h].filesz <= startOffset
		l.trimLoadSegments(startOffset, h)
	}

	neededSpace := l.ehsize() + uint64(len(l.ph))*l.phentsize()
	for _, s := range l.repl {
		neededSpace += roundUp(uint64(len(s)), l.word())
	}

	needWritable := false
	for name := range l.repl {
		if l.sh[l.must(name)].flags&shfWrite != 0 {
			needWritable = true
		}
	}

	var neededPages uint64
	switch {
	case reuseHeaderLoad:
		reservedPage := startAddr - startAddr%page
		var fileGrowth, virtualGrowth uint64
		if neededSpace > startOffset {
			fileGrowth = neededSpace - startOffset
		}
		if originalHeaderBase+neededSpace > reservedPage {
			virtualGrowth = originalHeaderBase + neededSpace - reservedPage
		}
		if g := max(fileGrowth, virtualGrowth); g != 0 {
			neededPages = roundUp(g, page) / page
		}
	case neededSpace > startOffset ||
		(needWritable && originalHeaderFlags&pfX != 0 && neededSpace+l.phentsize() <= startOffset && firstPage >= page):
		neededSpace += l.phentsize()
		startPageOff := startOffset - startOffset%page
		var growth uint64
		if neededSpace > startPageOff {
			growth = neededSpace - startPageOff
		}
		neededPages = roundUp(growth, page) / page
	}

	if neededPages != 0 {
		if neededPages*page > firstPage || (reuseHeaderLoad && neededPages*page > originalHeaderBase) {
			l.fail("virtual address space underrun")
		}
		var extra uint64
		if neededSpace > startOffset {
			extra = neededSpace - startOffset
		}
		l.shiftFile(neededPages, startOffset, extra)
		firstPage -= neededPages * page
		startOffset += neededPages * page
	}

	curOff := l.ehsize() + uint64(len(l.ph))*l.phentsize()
	headerBase := firstPage

	if h := l.findLoadByOffset(l.ehsize()); h >= 0 {
		headerBase = l.ph[h].vaddr - l.ph[h].off
		if l.ph[h].filesz < neededSpace {
			l.ph[h].filesz, l.ph[h].memsz = neededSpace, neededSpace
		}
		if needWritable {
			l.ph[h].flags |= pfW
		}
	}

	if startOffset < curOff || startOffset > uint64(len(l.data)) {
		l.fail("section offsets are inconsistent with file size")
	}
	clear(l.data[curOff:startOffset])

	l.writeReplacedSections(curOff, headerBase, 0)
	l.rewriteHeaders(headerBase + l.phoff())
}

func (l *layout) normalizeNoteSegments() {
	replacedNote := false
	for name := range l.repl {
		if l.sh[l.must(name)].typ == shtNote {
			replacedNote = true
		}
	}
	if !replacedNote {
		return
	}
	var added []phdr
	for i := range l.ph {
		p := &l.ph[i]
		if p.typ != ptNote {
			continue
		}
		start, end := p.off, p.off+p.filesz
		empty := true
		for _, s := range l.sh {
			if s.off >= start && s.off < end {
				empty = false
				break
			}
		}
		if empty {
			continue
		}
		cur := start
		for cur < end {
			var size uint64
			for _, s := range l.sh {
				if s.typ != shtNote {
					continue
				}
				align := max(1, s.addralign)
				if s.off != roundUp(cur, align) {
					continue
				}
				size = s.size
				cur = roundUp(cur, align)
				break
			}
			if size == 0 {
				l.fail("cannot normalize PT_NOTE segment: non-contiguous SHT_NOTE sections")
			}
			if cur+size > end {
				l.fail("cannot normalize PT_NOTE segment: partially mapped SHT_NOTE section")
			}
			n := *p
			n.off, n.vaddr, n.paddr = cur, p.vaddr+(cur-start), p.paddr+(cur-start)
			n.filesz, n.memsz = size, size
			if cur == start {
				*p = n
			} else {
				added = append(added, n)
			}
			cur += size
		}
	}
	l.ph = append(l.ph, added...)
	l.setPhnum(len(l.ph))
}

func (l *layout) dynEntSize() uint64 { return 2 * l.word() }

// rewriteHeaders writes the program and section header tables and fixes the
// addresses in .dynamic and the section indices in the symbol tables.
func (l *layout) rewriteHeaders(phdrAddress uint64) {
	for i := range l.ph {
		if l.ph[i].typ == ptPhdr {
			l.ph[i].off = l.phoff()
			l.ph[i].vaddr, l.ph[i].paddr = phdrAddress, phdrAddress
			sz := uint64(len(l.ph)) * l.phentsize()
			l.ph[i].filesz, l.ph[i].memsz = sz, sz
			break
		}
	}
	l.sortPhdrs()
	pe := l.phentsize()
	l.checkOff(l.phoff(), uint64(len(l.ph))*pe)
	for i, p := range l.ph {
		at := l.phoff() + uint64(i)*pe
		l.putPhdr(l.data[at:at+pe], p)
	}

	l.sortShdrs()
	se := l.shentsize()
	l.checkOff(l.shoff(), uint64(len(l.sh))*se)
	for i := 1; i < len(l.sh); i++ {
		at := l.shoff() + uint64(i)*se
		l.putShdr(l.data[at:at+se], l.sh[i])
	}

	if di := l.find(".dynamic"); di >= 0 && l.sh[di].typ != shtNobits {
		l.fixDynamic(l.sh[di])
	}
	l.remapSymbols()
}

func (l *layout) addrOf(names ...string) (uint64, bool) {
	for _, n := range names {
		if i := l.find(n); i >= 0 {
			return l.sh[i].addr, true
		}
	}
	return 0, false
}

func (l *layout) fixDynamic(dyn shdr) {
	b := l.secBytes(dyn)
	ent := l.dynEntSize()
	w := l.word()
	mustAddr := func(names ...string) uint64 {
		a, ok := l.addrOf(names...)
		if !ok {
			l.fail("cannot find section '%s'", names[0])
		}
		return a
	}
	for at := uint64(0); at+ent <= uint64(len(b)); at += ent {
		var tag int64
		if l.is32() {
			tag = int64(int32(l.order.Uint32(b[at:])))
		} else {
			tag = int64(l.order.Uint64(b[at:]))
		}
		if tag == dtNull {
			break
		}
		val := b[at+w : at+ent]
		set := func(v uint64) { l.ww(val, v) }
		switch tag {
		case dtStrtab:
			set(mustAddr(".dynstr"))
		case dtStrsz:
			set(l.sh[l.must(".dynstr")].size)
		case dtSymtab:
			set(mustAddr(".dynsym"))
		case dtHash:
			set(mustAddr(".hash"))
		case dtGnuHash:
			if a, ok := l.addrOf(".gnu.hash"); ok {
				set(a)
			}
		case dtMipsXhash:
			set(mustAddr(".MIPS.xhash"))
		case dtJmprel:
			a, ok := l.addrOf(".rel.plt", ".rela.plt", ".rela.IA_64.pltoff")
			if !ok {
				l.fail("cannot find section corresponding to DT_JMPREL")
			}
			set(a)
		case dtRel:
			if a, ok := l.addrOf(".rel.dyn", ".rel.got"); ok {
				set(a)
			}
		case dtRela:
			if a, ok := l.addrOf(".rela.dyn"); ok {
				set(a)
			}
		case dtVerneed:
			set(mustAddr(".gnu.version_r"))
		case dtVerdef:
			set(mustAddr(".gnu.version_d"))
		case dtVersym:
			set(mustAddr(".gnu.version"))
		case dtInitArray:
			if a, ok := l.addrOf(".init_array"); ok {
				set(a)
			}
		case dtFiniArray:
			if a, ok := l.addrOf(".fini_array"); ok {
				set(a)
			}
		case dtPreinitArray:
			if a, ok := l.addrOf(".preinit_array"); ok {
				set(a)
			}
		case dtMipsRldMapRel:
			if a, ok := l.addrOf(".rld_map"); ok {
				v := a - at - dyn.addr
				if l.is32() {
					v = uint64(uint32(v))
				}
				set(v)
			} else {
				set(0)
			}
		}
	}
}

// remapSymbols rewrites st_shndx (and st_value of section symbols) in every
// symbol table for the new section order.
func (l *layout) remapSymbols() {
	cur := map[int]int{} // section id -> current index
	for i, s := range l.sh {
		cur[s.id] = i
	}
	symSize := uint64(24)
	if l.is32() {
		symSize = 16
	}
	for i := 1; i < len(l.sh); i++ {
		s := l.sh[i]
		if s.typ != shtSymtab && s.typ != shtDynsym {
			continue
		}
		b := l.secBytes(s)
		for at := uint64(0); at+symSize <= uint64(len(b)); at += symSize {
			sym := b[at : at+symSize]
			var shndxAt, infoAt, valueAt int
			if l.is32() {
				shndxAt, infoAt, valueAt = 14, 12, 4
			} else {
				shndxAt, infoAt, valueAt = 6, 4, 8
			}
			shndx := int(l.order.Uint16(sym[shndxAt:]))
			if shndx == 0 || shndx >= 0xff00 || shndx >= len(l.basis) {
				continue
			}
			ni, ok := cur[l.basis[shndx]]
			if !ok {
				continue
			}
			l.order.PutUint16(sym[shndxAt:], uint16(ni))
			if sym[infoAt]&0xf == 3 { // STT_SECTION
				l.ww(sym[valueAt:], l.sh[ni].addr)
			}
		}
	}
	l.basis = l.basis[:0]
	for _, s := range l.sh {
		l.basis = append(l.basis, s.id)
	}
}
