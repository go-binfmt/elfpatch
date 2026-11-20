package elfpatch

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// verifyGrown judges a grown image. verify cannot: when the layout changes,
// "bytes outside the declared ranges are identical" is false by construction.
// What must hold instead is that the output is the input with the targeted
// fields changed and the layout changes the edit implies, and nothing else:
//
//   - the bytes written are the editor's image, which re-parses;
//   - the ELF header is unchanged but for the table offsets and counts;
//   - every section is still there with the same type, flags, links and
//     contents, at the same address unless it is one that may move (anything
//     but PROGBITS, plus .interp); only .interp, .dynstr and .dynamic, the
//     ones an edit replaces, may change size or contents, and those only as
//     the edit says (strings appended, entries added or removed, addresses
//     following their section);
//   - every string reference (symbol names, version names) still reads the same
//     string, with the renamed DT_NEEDED the one allowed difference;
//   - every untouched field of the snapshot reads back unchanged;
//   - the program headers describe the new file: every allocated section sits
//     in a PT_LOAD at the offset its address implies, with the permissions its
//     flags need; PT_INTERP, PT_DYNAMIC and PT_PHDR match their section or
//     table; the other segments keep their addresses and sizes; the PT_LOADs
//     do not overlap and are congruent with their file offsets.
func verifyGrown(orig, out []byte, f *File) error {
	if !bytes.Equal(out, f.data) {
		return fmt.Errorf("%w: written bytes differ from the editor's image", ErrVerify)
	}
	o, err := Parse(orig)
	if err != nil {
		return err
	}
	g, err := Parse(out)
	if err != nil {
		return fmt.Errorf("%w: output does not parse: %v", ErrVerify, err)
	}
	if err := compareSnaps(o, g, f.touched); err != nil {
		return err
	}
	lo, err := loadLayout(orig, 0)
	if err != nil {
		return err
	}
	lg, err := loadLayout(out, 0)
	if err != nil {
		return fmt.Errorf("%w: output layout: %v", ErrVerify, err)
	}
	err = lg.run(func() { checkGrown(lo, lg, f) })
	if err != nil && !errors.Is(err, ErrVerify) {
		err = fmt.Errorf("%w: %v", ErrVerify, err)
	}
	return err
}

// vfail panics with a verification error; checkGrown is run under l.run.
func (l *layout) vfail(format string, a ...any) {
	panic(layoutError{fmt.Errorf("%w: %s", ErrVerify, fmt.Sprintf(format, a...))})
}

type dent struct {
	tag int64
	val uint64
}

// dynList reads the dynamic entries of section s up to DT_NULL.
func (l *layout) dynList(s shdr) []dent {
	b := l.secBytes(s)
	ent, w := l.dynEntSize(), l.word()
	var out []dent
	for at := uint64(0); at+ent <= uint64(len(b)); at += ent {
		var tag int64
		if l.is32() {
			tag = int64(int32(l.order.Uint32(b[at:])))
		} else {
			tag = int64(l.order.Uint64(b[at:]))
		}
		if tag == dtNull {
			return out
		}
		out = append(out, dent{tag, l.rw(b[at+w:])})
	}
	l.vfail(".dynamic has no DT_NULL")
	return nil
}

// groups indexes sections 1.. by name, each group in file-offset order.
func (l *layout) groups() map[string][]int {
	m := map[string][]int{}
	for i := 1; i < len(l.sh); i++ {
		m[l.secName(i)] = append(m[l.secName(i)], i)
	}
	for _, g := range m {
		slices.SortStableFunc(g, func(a, b int) int { return cmp.Compare(l.sh[a].off, l.sh[b].off) })
	}
	return m
}

func (l *layout) cstr(sec shdr, o uint64) (string, bool) {
	if sec.typ == shtNobits || o >= sec.size || !inRange(sec.off, sec.size, uint64(len(l.data))) {
		return "", false
	}
	b := l.data[sec.off+o : sec.off+sec.size]
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), true
		}
	}
	return "", false
}

const (
	shfAlloc = 2
	shfExec  = 4
	shfTLS   = 0x400
)

func checkGrown(a, b *layout, f *File) {
	// ELF header: everything but the table offsets and counts.
	ha, hb := slices.Clone(a.data[:a.ehsize()]), slices.Clone(b.data[:b.ehsize()])
	for _, l := range []struct {
		h []byte
		l *layout
	}{{ha, a}, {hb, b}} {
		clear(l.h[l.l.atPhoff() : l.l.atPhoff()+int(l.l.word())])
		clear(l.h[l.l.atShoff() : l.l.atShoff()+int(l.l.word())])
		clear(l.h[l.l.atPhnum() : l.l.atPhnum()+2])
		clear(l.h[l.l.atShnum() : l.l.atShnum()+2])
		clear(l.h[l.l.atShstrndx() : l.l.atShstrndx()+2])
	}
	if !bytes.Equal(ha, hb) {
		b.vfail("ELF header changed")
	}

	ga, gb := a.groups(), b.groups()
	if len(ga) != len(gb) {
		b.vfail("the set of sections changed")
	}
	pair := map[int]int{0: 0}
	for name, ia := range ga {
		ib := gb[name]
		if len(ia) != len(ib) {
			b.vfail("section %s: %d before, %d after", name, len(ia), len(ib))
		}
		for k := range ia {
			pair[ia[k]] = ib[k]
		}
	}
	if ka, kb := a.shstrndx(), b.shstrndx(); pair[ka] != kb {
		b.vfail("the section name table moved to another section")
	}

	replaced := func(name string) bool { return slices.Contains(f.sections, name) }
	for ia := 1; ia < len(a.sh); ia++ {
		ib := pair[ia]
		sa, sb := a.sh[ia], b.sh[ib]
		name := a.secName(ia)
		if sa.typ != sb.typ || sa.flags != sb.flags || sa.entsize != sb.entsize {
			b.vfail("section %s: type, flags or entry size changed", name)
		}
		if a.secName(int(sa.link)) != b.secName(int(sb.link)) {
			b.vfail("section %s: sh_link changed", name)
		}
		if sa.typ == shtRel || sa.typ == shtRela {
			if a.secName(int(sa.info)) != b.secName(int(sb.info)) {
				b.vfail("section %s: sh_info changed", name)
			}
		} else if sa.info != sb.info {
			b.vfail("section %s: sh_info changed", name)
		}
		moved := sa.addr != sb.addr
		if moved && sa.typ == shtProgbits && name != ".interp" {
			b.vfail("section %s (PROGBITS) moved from %#x to %#x", name, sa.addr, sb.addr)
		}
		if !replaced(name) && sa.size != sb.size {
			b.vfail("section %s changed size %d -> %d", name, sa.size, sb.size)
		}
		// A relocated section is aligned to the word size (patchelf); nothing else
		// may change its alignment.
		if sa.addralign != sb.addralign && sb.addralign != b.word() {
			b.vfail("section %s: alignment %d became %d", name, sa.addralign, sb.addralign)
		}
		if sa.typ == shtNobits {
			continue
		}
		ca, cb := a.secBytes(sa), b.secBytes(sb)
		switch {
		case name == ".interp":
			// judged through the snapshot and PT_INTERP
		case name == ".dynstr":
			if len(cb) < len(ca) || len(ca) == 0 || cb[0] != ca[0] || cb[len(cb)-1] != 0 {
				b.vfail(".dynstr is not the old table plus appended strings")
			}
		case name == ".dynamic":
			checkDynamic(a, b, sa, sb, f)
		case sa.typ == shtSymtab || sa.typ == shtDynsym:
			checkSymbols(a, b, sa, sb, pair, name)
		case sa.typ == shtVerneedType:
			if !bytes.Equal(stripVnFile(a, ca), stripVnFile(b, cb)) {
				b.vfail("section %s changed beyond the file names", name)
			}
		default:
			if !bytes.Equal(ca, cb) {
				b.vfail("section %s: contents changed", name)
			}
		}
	}

	checkStrings(a, b, f)
	checkSegments(a, b)
}

const shtVerneedType = 0x6ffffffe

// stripVnFile returns a copy of a .gnu.version_r with every vn_file zeroed.
func stripVnFile(l *layout, b []byte) []byte {
	c := slices.Clone(b)
	off := uint64(0)
	for steps := 0; steps < len(b); steps++ {
		if !inRange(off, 16, uint64(len(c))) {
			break
		}
		clear(c[off+4 : off+8])
		next := uint64(l.order.Uint32(c[off+12:]))
		if next == 0 {
			break
		}
		off += next
	}
	return c
}

var dynPointerSections = map[int64][]string{
	dtStrtab:       {".dynstr"},
	dtSymtab:       {".dynsym"},
	dtHash:         {".hash"},
	dtGnuHash:      {".gnu.hash"},
	dtJmprel:       {".rel.plt", ".rela.plt", ".rela.IA_64.pltoff"},
	dtRel:          {".rel.dyn", ".rel.got"},
	dtRela:         {".rela.dyn"},
	dtVerneed:      {".gnu.version_r"},
	dtVerdef:       {".gnu.version_d"},
	dtVersym:       {".gnu.version"},
	dtInitArray:    {".init_array"},
	dtFiniArray:    {".fini_array"},
	dtPreinitArray: {".preinit_array"},
}

func checkDynamic(a, b *layout, sa, sb shdr, f *File) {
	drop := func(es []dent) []dent {
		return slices.DeleteFunc(slices.Clone(es), func(e dent) bool {
			return e.tag == dtNeeded || e.tag == dtSoname || e.tag == dtRpath || e.tag == dtRunpath
		})
	}
	da, db := drop(a.dynList(sa)), drop(b.dynList(sb))
	if len(da) != len(db) {
		b.vfail(".dynamic: %d other entries before, %d after", len(da), len(db))
	}
	for i := range da {
		x, y := da[i], db[i]
		if x.tag != y.tag {
			b.vfail(".dynamic entry %d: tag %d became %d", i, x.tag, y.tag)
		}
		want := x.val
		if names, ok := dynPointerSections[x.tag]; ok {
			if aa, ok := a.addrOf(names...); ok && aa == x.val {
				want, _ = b.addrOf(names...)
			}
		} else if x.tag == dtStrsz {
			if x.val == a.sh[a.must(".dynstr")].size {
				want = b.sh[b.must(".dynstr")].size
			}
		} else if x.tag == dtMipsRldMapRel {
			continue
		}
		if y.val != want {
			b.vfail(".dynamic entry %d (tag %#x): value %#x, want %#x", i, x.tag, y.val, want)
		}
	}
}

func checkSymbols(a, b *layout, sa, sb shdr, pair map[int]int, name string) {
	ent := uint64(24)
	shndxAt, infoAt, valueAt, sizeAt := 6, 4, 8, 16
	if a.is32() {
		ent = 16
		shndxAt, infoAt, valueAt, sizeAt = 14, 12, 4, 8
	}
	ca, cb := a.secBytes(sa), b.secBytes(sb)
	if len(ca) != len(cb) {
		b.vfail("%s changed size", name)
	}
	for at := uint64(0); at+ent <= uint64(len(ca)); at += ent {
		x, y := ca[at:at+ent], cb[at:at+ent]
		same := bytes.Equal(x[:4], y[:4]) && x[infoAt] == y[infoAt] && x[infoAt+1] == y[infoAt+1] &&
			bytes.Equal(x[sizeAt:sizeAt+int(a.word())], y[sizeAt:sizeAt+int(a.word())])
		if !same {
			b.vfail("%s symbol %d changed", name, at/ent)
		}
		xi, yi := int(a.order.Uint16(x[shndxAt:])), int(b.order.Uint16(y[shndxAt:]))
		switch {
		case xi == 0 || xi >= 0xff00:
			if xi != yi {
				b.vfail("%s symbol %d: section index %d became %d", name, at/ent, xi, yi)
			}
		case xi >= len(a.sh) || pair[xi] != yi:
			b.vfail("%s symbol %d: section index %d became %d", name, at/ent, xi, yi)
		}
		xv, yv := a.rw(x[valueAt:]), b.rw(y[valueAt:])
		if x[infoAt]&0xf == 3 && yi < len(b.sh) { // STT_SECTION follows its section
			xv = b.sh[yi].addr
		}
		if xv != yv {
			b.vfail("%s symbol %d: value %#x became %#x", name, at/ent, xv, yv)
		}
	}
}

// strings reads every string a section other than .dynamic refers to.
func collectStrings(l *layout, renamed map[string]string) []string {
	var out []string
	str := func(sec shdr, o uint64, what string) string {
		s, ok := l.cstr(sec, o)
		if !ok {
			l.vfail("%s: string offset %d outside its table", what, o)
		}
		return s
	}
	for i := 1; i < len(l.sh); i++ {
		s := l.sh[i]
		if s.typ == shtNobits {
			continue
		}
		switch s.typ {
		case shtDynsym:
			tab := l.sh[s.link]
			b := l.secBytes(s)
			ent := uint64(24)
			if l.is32() {
				ent = 16
			}
			for at := uint64(0); at+ent <= uint64(len(b)); at += ent {
				out = append(out, l.secName(i)+"|sym:"+str(tab, uint64(l.order.Uint32(b[at:])), "dynsym"))
			}
		case shtVerneedType:
			tab := l.sh[s.link]
			b := l.secBytes(s)
			off := uint64(0)
			for steps := 0; steps < len(b); steps++ {
				if !inRange(off, 16, uint64(len(b))) {
					l.vfail("Verneed outside its section")
				}
				file := str(tab, uint64(l.order.Uint32(b[off+4:])), "vn_file")
				if r, ok := renamed[file]; ok {
					file = r
				}
				out = append(out, l.secName(i)+"|need-file:"+file)
				cnt := uint64(l.order.Uint16(b[off+2:]))
				ao := off + uint64(l.order.Uint32(b[off+8:]))
				for j := uint64(0); j < cnt; j++ {
					if !inRange(ao, 16, uint64(len(b))) {
						l.vfail("Vernaux outside its section")
					}
					out = append(out, l.secName(i)+"|need-aux:"+str(tab, uint64(l.order.Uint32(b[ao+8:])), "vna_name"))
					an := uint64(l.order.Uint32(b[ao+12:]))
					if an == 0 {
						break
					}
					ao += an
				}
				next := uint64(l.order.Uint32(b[off+12:]))
				if next == 0 {
					break
				}
				off += next
			}
		case 0x6ffffffd: // SHT_GNU_verdef
			tab := l.sh[s.link]
			b := l.secBytes(s)
			off := uint64(0)
			for steps := 0; steps < len(b); steps++ {
				if !inRange(off, 20, uint64(len(b))) {
					l.vfail("Verdef outside its section")
				}
				cnt := uint64(l.order.Uint16(b[off+6:]))
				ao := off + uint64(l.order.Uint32(b[off+12:]))
				for j := uint64(0); j < cnt; j++ {
					if !inRange(ao, 8, uint64(len(b))) {
						l.vfail("Verdaux outside its section")
					}
					out = append(out, l.secName(i)+"|def:"+str(tab, uint64(l.order.Uint32(b[ao:])), "vda_name"))
					an := uint64(l.order.Uint32(b[ao+4:]))
					if an == 0 {
						break
					}
					ao += an
				}
				next := uint64(l.order.Uint32(b[off+16:]))
				if next == 0 {
					break
				}
				off += next
			}
		}
	}
	if di := l.find(".dynamic"); di >= 0 {
		ds := l.sh[di]
		tab := l.sh[l.must(".dynstr")]
		for _, e := range l.dynList(ds) {
			if e.tag == 0x7ffffffd || e.tag == 0x7fffffff {
				out = append(out, fmt.Sprintf(".dynamic|dyn%#x:%s", e.tag, str(tab, e.val, "dynamic")))
			}
		}
	}
	// section order is not preserved by a rewrite; order within a section is
	slices.SortStableFunc(out, func(x, y string) int {
		return strings.Compare(x[:strings.IndexByte(x, '|')], y[:strings.IndexByte(y, '|')])
	})
	return out
}

func checkStrings(a, b *layout, f *File) {
	sa, sb := collectStrings(a, f.renamed), collectStrings(b, nil)
	if len(sa) != len(sb) {
		b.vfail("%d symbol and version name references became %d", len(sa), len(sb))
	}
	for i := range sa {
		if sa[i] != sb[i] {
			b.vfail("a string reference changed: %q became %q", sa[i], sb[i])
		}
	}
}

func checkSegments(a, b *layout) {
	n := uint64(len(b.data))
	var loads []phdr
	for _, p := range b.ph {
		if p.typ == ptLoad {
			loads = append(loads, p)
		}
	}
	if len(loads) == 0 {
		b.vfail("no PT_LOAD")
	}
	wx := func(l *layout) (c int) {
		for _, p := range l.ph {
			if p.typ == ptLoad && p.flags&pfW != 0 && p.flags&pfX != 0 {
				c++
			}
		}
		return
	}
	if wx(b) > wx(a) {
		b.vfail("a PT_LOAD became writable and executable")
	}
	for _, p := range loads {
		if !inRange(p.off, p.filesz, n) || p.memsz < p.filesz {
			b.vfail("PT_LOAD [%#x,+%#x) is outside the file or smaller than its file part", p.off, p.filesz)
		}
		if p.align > 1 && (p.vaddr-p.off)%p.align != 0 {
			b.vfail("PT_LOAD at %#x is not congruent with offset %#x modulo %#x", p.vaddr, p.off, p.align)
		}
	}
	sorted := slices.Clone(loads)
	slices.SortFunc(sorted, func(x, y phdr) int { return cmp.Compare(x.vaddr, y.vaddr) })
	for i := 1; i < len(sorted); i++ {
		if sorted[i-1].vaddr+sorted[i-1].memsz > sorted[i].vaddr {
			b.vfail("PT_LOADs overlap in memory at %#x", sorted[i].vaddr)
		}
	}
	// within returns the LOAD that holds [addr, addr+size) in its file part
	// (or its memory image when mem is set).
	within := func(addr, size uint64, mem bool) (phdr, bool) {
		for _, p := range loads {
			lim := p.filesz
			if mem {
				lim = p.memsz
			}
			if addr >= p.vaddr && addr-p.vaddr <= lim && size <= lim-(addr-p.vaddr) {
				return p, true
			}
		}
		return phdr{}, false
	}
	for i := 1; i < len(b.sh); i++ {
		s := b.sh[i]
		if s.flags&shfAlloc == 0 || s.size == 0 {
			continue
		}
		name := b.secName(i)
		if s.typ == shtNobits {
			if s.flags&shfTLS != 0 {
				continue
			}
			if _, ok := within(s.addr, s.size, true); !ok {
				b.vfail("section %s [%#x,+%#x) is not in any PT_LOAD", name, s.addr, s.size)
			}
			continue
		}
		p, ok := within(s.addr, s.size, false)
		if !ok || p.off+(s.addr-p.vaddr) != s.off {
			b.vfail("section %s at %#x does not sit at file offset %#x in a PT_LOAD", name, s.addr, s.off)
		}
		if s.flags&shfWrite != 0 && p.flags&pfW == 0 {
			b.vfail("writable section %s is in a read-only PT_LOAD", name)
		}
		if s.flags&shfExec != 0 && p.flags&pfX == 0 {
			b.vfail("executable section %s is in a non-executable PT_LOAD", name)
		}
	}
	for _, p := range b.ph {
		if p.typ == ptLoad || p.filesz == 0 {
			continue
		}
		l, ok := within(p.vaddr, p.filesz, false)
		if !ok || l.off+(p.vaddr-l.vaddr) != p.off {
			b.vfail("segment type %#x at %#x is not mapped at its file offset %#x", p.typ, p.vaddr, p.off)
		}
	}
	for _, p := range b.ph {
		switch p.typ {
		case ptInterp:
			s := b.sh[b.must(".interp")]
			if p.off != s.off || p.filesz != s.size {
				b.vfail("PT_INTERP does not match .interp")
			}
		case ptDynamic:
			s := b.sh[b.must(".dynamic")]
			if p.off != s.off || p.filesz != s.size || p.vaddr != s.addr {
				b.vfail("PT_DYNAMIC does not match .dynamic")
			}
		case ptPhdr:
			if p.off != b.phoff() || p.filesz != uint64(len(b.ph))*b.phentsize() {
				b.vfail("PT_PHDR does not match the program header table")
			}
		}
	}
	// The other segments keep their kind, permissions, alignment and (where
	// they do not follow a moved section) address and size.
	moves := map[uint32]bool{ptPhdr: true, ptInterp: true, ptDynamic: true, ptMipsAbiflags: true, ptGnuProperty: true}
	kinds := func(l *layout) map[uint32][]phdr {
		m := map[uint32][]phdr{}
		for _, p := range l.ph {
			if p.typ != ptLoad && p.typ != ptNote {
				m[p.typ] = append(m[p.typ], p)
			}
		}
		return m
	}
	ka, kb := kinds(a), kinds(b)
	if len(ka) != len(kb) {
		b.vfail("the set of segment types changed")
	}
	for typ, xs := range ka {
		ys := kb[typ]
		if len(xs) != len(ys) {
			b.vfail("segment type %#x: %d before, %d after", typ, len(xs), len(ys))
		}
		for i, x := range xs {
			y := ys[i]
			if x.flags != y.flags || x.align != y.align && !moves[typ] {
				b.vfail("segment type %#x: flags or alignment changed", typ)
			}
			if !moves[typ] && (x.vaddr != y.vaddr || x.memsz != y.memsz || x.filesz != y.filesz) {
				b.vfail("segment type %#x: address or size changed", typ)
			}
		}
	}
}
