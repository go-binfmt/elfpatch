// Package elfpatch reads and edits the dynamic-linking metadata of ELF files
// in pure Go: PT_INTERP, DT_RPATH/DT_RUNPATH, DT_NEEDED and DT_SONAME. It is a
// sovereign replacement for the subset of NixOS patchelf that package
// builders use.
//
// Phase 1 edits IN PLACE only: a value that does not fit the slot the linker
// reserved is refused with a typed error (ErrNoSpace), never truncated, and
// nothing is written. Growing .dynstr or PT_INTERP (adding a PT_LOAD, as
// patchelf does) is phase 2.
//
// The parser works on program headers only (PT_INTERP, PT_DYNAMIC, PT_LOAD),
// so stripped files without section headers are handled, and every offset and
// size is checked against the file length without overflowing uint64.
package elfpatch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Sentinel errors. Use errors.Is.
var (
	ErrNotELF      = errors.New("elfpatch: not an ELF file")
	ErrCorrupt     = errors.New("elfpatch: malformed ELF")
	ErrUnsupported = errors.New("elfpatch: unsupported ELF feature")
	// ErrNoSpace means the new value is longer than the slot reserved in the
	// file. Phase 2 grows the slot; phase 1 refuses.
	ErrNoSpace = errors.New("elfpatch: new value does not fit in place (needs growth, phase 2)")
	// ErrNoInterp: the file has no PT_INTERP (shared libraries mostly).
	ErrNoInterp = errors.New("elfpatch: no PT_INTERP")
	// ErrNoDynamic: the file has no PT_DYNAMIC (statically linked).
	ErrNoDynamic = errors.New("elfpatch: no PT_DYNAMIC (statically linked?)")
	// ErrNoRpath: no DT_RPATH/DT_RUNPATH to edit in place; adding one needs a
	// free dynamic slot or growth (phase 2).
	ErrNoRpath = errors.New("elfpatch: no DT_RPATH/DT_RUNPATH entry (adding one is phase 2)")
	// ErrAmbiguous: the file is shaped in a way an in-place edit cannot honour
	// without guessing (both RPATH and RUNPATH, or a string shared with
	// another reference).
	ErrAmbiguous = errors.New("elfpatch: ambiguous layout, refusing to edit in place")
	// ErrVerify: the output did not re-parse as the input plus the targeted
	// change. Nothing was written.
	ErrVerify = errors.New("elfpatch: post-write verification failed")
)

// NoSpaceError carries the numbers behind ErrNoSpace.
type NoSpaceError struct {
	Field string // "interpreter", "rpath", "needed"
	Have  uint64 // bytes available, NUL included
	Need  uint64 // bytes required, NUL included
	// Cause is why growth could not place the value either (no section
	// headers, a layout patchelf refuses, ...); nil from the in-place editors.
	Cause error
}

func (e *NoSpaceError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("elfpatch: %s needs %d bytes but the slot holds %d, and the file cannot be grown: %v", e.Field, e.Need, e.Have, e.Cause)
	}
	return fmt.Sprintf("elfpatch: %s needs %d bytes but the slot holds %d: %v", e.Field, e.Need, e.Have, ErrNoSpace)
}

// Unwrap exposes ErrNoSpace and, when growth was tried, why it failed.
func (e *NoSpaceError) Unwrap() []error {
	if e.Cause != nil {
		return []error{ErrNoSpace, e.Cause}
	}
	return []error{ErrNoSpace}
}

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, a...))
}

// ELF constants used here.
const (
	ptLoad    = 1
	ptDynamic = 2
	ptInterp  = 3

	dtNull     = 0
	dtNeeded   = 1
	dtHash     = 4
	dtStrtab   = 5
	dtSymtab   = 6
	dtStrsz    = 10
	dtSoname   = 14
	dtRpath    = 15
	dtRunpath  = 29
	dtVerdef   = 0x6ffffffc
	dtVerdefN  = 0x6ffffffd
	dtVerneed  = 0x6ffffffe
	dtVerneedN = 0x6fffffff
	dtGnuHash  = 0x6ffffef5
)

// maxFile bounds what we load: it also keeps every offset inside int on 32-bit
// platforms. A variable only so a test can lower it.
var maxFile uint64 = math.MaxInt32

type prog struct {
	typ           uint32
	off, vaddr    uint64
	filesz, memsz uint64
	hdrOff        uint64 // where this header sits in the file
}

type dynEnt struct {
	tag int64
	val uint64
	off uint64 // file offset of this entry
}

// File is a parsed ELF image held in memory.
type File struct {
	Class   int // 32 or 64
	Order   binary.ByteOrder
	Type    uint16
	Machine uint16

	data  []byte
	progs []prog

	interp *prog

	dynProg *prog
	entSize uint64
	dyn     []dynEnt // entries before the first DT_NULL

	strOff, strLen uint64 // dynstr, as file offsets; strLen 0 when absent
	hasStr         bool

	allowed []rng // byte ranges the edits declared (see File.write)
	closer  func() error
	touched touched

	// Growth bookkeeping (phase 2). grown is set once an edit rewrote the
	// layout: data is then a new image, and the verifier judges it by
	// structure instead of by declared byte ranges.
	grown      bool
	forcedPage uint64            // --page-size, 0 = by e_machine
	sections   []string          // sections an edit replaced (.interp, .dynstr, .dynamic)
	renamed    map[string]string // DT_NEEDED renames, for the version-needed check
}

type rng struct{ off, end uint64 }

type touched uint8

const (
	tInterp touched = 1 << iota
	tNeeded
	tSoname
	tRpath
	tRunpath
)

// Bytes returns the image (shared, not a copy).
func (f *File) Bytes() []byte { return f.data }

// inRange reports off+size <= n without overflow.
func inRange(off, size, n uint64) bool { return off <= n && size <= n-off }

// Parse parses an ELF image. The slice is retained and edited in place by the
// mutation methods; use Patch for the verified, atomic file workflow.
func Parse(data []byte) (*File, error) {
	if uint64(len(data)) > maxFile {
		return nil, fmt.Errorf("%w: file larger than 2 GiB", ErrUnsupported)
	}
	if len(data) < 16 || string(data[:4]) != "\x7fELF" {
		return nil, ErrNotELF
	}
	f := &File{data: data}
	switch data[4] {
	case 1:
		f.Class = 32
	case 2:
		f.Class = 64
	default:
		return nil, corrupt("EI_CLASS %d", data[4])
	}
	switch data[5] {
	case 1:
		f.Order = binary.LittleEndian
	case 2:
		f.Order = binary.BigEndian
	default:
		return nil, corrupt("EI_DATA %d", data[5])
	}
	if data[6] != 1 {
		return nil, corrupt("EI_VERSION %d", data[6])
	}
	var phoff uint64
	var phentsize, phnum uint16
	n := uint64(len(data))
	if f.Class == 32 {
		if n < 52 {
			return nil, corrupt("truncated header")
		}
		phoff = uint64(f.Order.Uint32(data[28:]))
		phentsize, phnum = f.Order.Uint16(data[42:]), f.Order.Uint16(data[44:])
	} else {
		if n < 64 {
			return nil, corrupt("truncated header")
		}
		phoff = f.Order.Uint64(data[32:])
		phentsize, phnum = f.Order.Uint16(data[54:]), f.Order.Uint16(data[56:])
	}
	f.Type, f.Machine = f.Order.Uint16(data[16:]), f.Order.Uint16(data[18:])

	if phnum == 0xffff {
		return nil, fmt.Errorf("%w: extended program header count (PN_XNUM)", ErrUnsupported)
	}
	if phnum == 0 {
		return f, nil
	}
	want := uint16(32)
	if f.Class == 64 {
		want = 56
	}
	if phentsize != want {
		return nil, corrupt("e_phentsize %d, want %d", phentsize, want)
	}
	total := uint64(phnum) * uint64(phentsize)
	if !inRange(phoff, total, n) {
		return nil, corrupt("program headers [%d,+%d) outside file of %d bytes", phoff, total, n)
	}
	for i := uint64(0); i < uint64(phnum); i++ {
		at := phoff + i*uint64(phentsize)
		b := data[at : at+uint64(phentsize)]
		var p prog
		p.hdrOff = at
		p.typ = f.Order.Uint32(b)
		if f.Class == 32 {
			p.off, p.vaddr = uint64(f.Order.Uint32(b[4:])), uint64(f.Order.Uint32(b[8:]))
			p.filesz, p.memsz = uint64(f.Order.Uint32(b[16:])), uint64(f.Order.Uint32(b[20:]))
		} else {
			p.off, p.vaddr = f.Order.Uint64(b[8:]), f.Order.Uint64(b[16:])
			p.filesz, p.memsz = f.Order.Uint64(b[32:]), f.Order.Uint64(b[40:])
		}
		if p.filesz > 0 && !inRange(p.off, p.filesz, n) {
			return nil, corrupt("program header %d: [%d,+%d) outside file of %d bytes", i, p.off, p.filesz, n)
		}
		f.progs = append(f.progs, p)
	}
	for i := range f.progs {
		p := &f.progs[i]
		switch {
		case p.typ == ptInterp && f.interp == nil:
			f.interp = p
		case p.typ == ptDynamic && f.dynProg == nil:
			f.dynProg = p
		}
	}
	if f.interp != nil && f.interp.filesz == 0 {
		return nil, corrupt("empty PT_INTERP")
	}
	if err := f.loadDynamic(); err != nil {
		return nil, err
	}
	return f, nil
}

// loadDynamic (re)reads PT_DYNAMIC and locates .dynstr.
func (f *File) loadDynamic() error {
	f.dyn, f.hasStr, f.strOff, f.strLen = nil, false, 0, 0
	p := f.dynProg
	if p == nil {
		return nil
	}
	f.entSize = 16
	if f.Class == 32 {
		f.entSize = 8
	}
	cnt := p.filesz / f.entSize
	var strtab, strsz uint64
	var haveTab, haveSz bool
	for i := uint64(0); i < cnt; i++ {
		at := p.off + i*f.entSize
		b := f.data[at : at+f.entSize]
		var e dynEnt
		e.off = at
		if f.Class == 32 {
			e.tag, e.val = int64(int32(f.Order.Uint32(b))), uint64(f.Order.Uint32(b[4:]))
		} else {
			e.tag, e.val = int64(f.Order.Uint64(b)), f.Order.Uint64(b[8:])
		}
		if e.tag == dtNull {
			break
		}
		switch e.tag {
		case dtStrtab:
			if !haveTab {
				strtab, haveTab = e.val, true
			}
		case dtStrsz:
			if !haveSz {
				strsz, haveSz = e.val, true
			}
		}
		f.dyn = append(f.dyn, e)
	}
	if haveTab && !haveSz {
		return corrupt("DT_STRTAB without DT_STRSZ")
	}
	if haveTab {
		off, ok := f.vaddrToOff(strtab)
		if !ok || !inRange(off, strsz, uint64(len(f.data))) {
			return corrupt("DT_STRTAB %#x size %d outside any PT_LOAD or the file", strtab, strsz)
		}
		f.hasStr, f.strOff, f.strLen = true, off, strsz
	}
	return nil
}

func (f *File) vaddrToOff(a uint64) (uint64, bool) {
	for i := range f.progs {
		p := &f.progs[i]
		if p.typ == ptLoad && a >= p.vaddr && a-p.vaddr < p.filesz {
			return p.off + (a - p.vaddr), true
		}
	}
	return 0, false
}

// strAt returns the NUL-terminated dynstr string at rel offset o and the
// number of bytes before its NUL.
func (f *File) strAt(o uint64) (string, error) {
	if !f.hasStr || o >= f.strLen {
		return "", corrupt("string offset %d outside .dynstr (%d bytes)", o, f.strLen)
	}
	b := f.data[f.strOff+o : f.strOff+f.strLen]
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), nil
		}
	}
	return "", corrupt("unterminated string at .dynstr+%d", o)
}

func (f *File) firstDyn(tags ...int64) (int, bool) {
	for i, e := range f.dyn {
		for _, t := range tags {
			if e.tag == t {
				return i, true
			}
		}
	}
	return 0, false
}

func (f *File) dynString(tag int64) (string, bool, error) {
	i, ok := f.firstDyn(tag)
	if !ok {
		return "", false, nil
	}
	s, err := f.strAt(f.dyn[i].val)
	return s, true, err
}

// Interpreter returns the PT_INTERP string; ok is false when there is none.
func (f *File) Interpreter() (s string, ok bool, err error) {
	p := f.interp
	if p == nil {
		return "", false, nil
	}
	b := f.data[p.off : p.off+p.filesz]
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), true, nil
		}
	}
	return "", true, corrupt("PT_INTERP is not NUL-terminated")
}

// Needed returns the DT_NEEDED names in order.
func (f *File) Needed() ([]string, error) {
	var out []string
	for _, e := range f.dyn {
		if e.tag == dtNeeded {
			s, err := f.strAt(e.val)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
	}
	return out, nil
}

// Soname returns DT_SONAME; ok is false when absent.
func (f *File) Soname() (string, bool, error) { return f.dynString(dtSoname) }

// Rpath returns DT_RPATH; ok is false when absent.
func (f *File) Rpath() (string, bool, error) { return f.dynString(dtRpath) }

// Runpath returns DT_RUNPATH; ok is false when absent.
func (f *File) Runpath() (string, bool, error) { return f.dynString(dtRunpath) }

// SearchPath returns what patchelf --print-rpath prints: DT_RUNPATH if
// present, else DT_RPATH.
func (f *File) SearchPath() (string, bool, error) {
	if s, ok, err := f.Runpath(); ok || err != nil {
		return s, ok, err
	}
	return f.Rpath()
}
