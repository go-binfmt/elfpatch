package elfpatch

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Growth (phase 2). An edit that does not fit in place is carried out the way
// patchelf does it: the string is appended to .dynstr (or .interp is rewritten,
// or an entry is added to .dynamic), the section that grew is replaced by a
// larger copy placed in new space, and the headers are rewritten (layout.go).
// The image is then re-parsed; a layout that does not parse is an error and
// nothing is written.

// adopt replaces the parsed state with a freshly parsed image of data (the
// result of a layout rewrite), keeping the bookkeeping of the running edit.
func (f *File) adopt(data []byte) error {
	g, err := Parse(data)
	if err != nil {
		return fmt.Errorf("%w: the grown image does not parse: %v", ErrVerify, err)
	}
	g.allowed, g.touched, g.closer = f.allowed, f.touched, f.closer
	g.forcedPage, g.renamed, g.sections = f.forcedPage, f.renamed, f.sections
	g.grown = true
	*f = *g
	return nil
}

// relayout runs edit on a layout of the current image and then rewrites the
// replaced sections. sections names the sections the edit replaces, for the
// verifier.
func (f *File) relayout(sections []string, edit func(l *layout)) error {
	l, err := loadLayout(f.data, f.forcedPage)
	if err != nil {
		return err
	}
	if err := l.run(func() {
		edit(l)
		l.rewriteSections()
	}); err != nil {
		return err
	}
	for _, s := range sections {
		if !slices.Contains(f.sections, s) {
			f.sections = append(f.sections, s)
		}
	}
	return f.adopt(l.data)
}

// growErr is the refusal for an edit that needed growth and could not have it.
// A value that would have fitted but for a string shared with another name is
// ErrAmbiguous, as in place; one that is too long is ErrNoSpace. Both carry why
// the file could not be grown.
func growErr(field string, have, need uint64, shared bool, cause error) error {
	if need <= have && shared {
		return fmt.Errorf("%w: another name points into the %s string, and the file cannot be grown: %v", ErrAmbiguous, field, cause)
	}
	return &NoSpaceError{Field: field, Have: have, Need: need, Cause: cause}
}

// appendStrings appends NUL-terminated strings to the string section and
// returns their offsets.
func (l *layout) appendStrings(section string, strs []string) []uint64 {
	var base uint64
	if r, ok := l.repl[section]; ok {
		base = uint64(len(r))
	} else {
		base = l.sh[l.must(section)].size
	}
	total := base
	for _, s := range strs {
		total += uint64(len(s)) + 1
	}
	buf := l.replaceSection(section, total)
	offs := make([]uint64, 0, len(strs))
	pos := base
	for _, s := range strs {
		copy(buf[pos:], s)
		offs = append(offs, pos)
		pos += uint64(len(s)) + 1
	}
	return offs
}

type dynNew struct {
	tag int64
	val uint64
}

// prependDynamic inserts entries at the top of .dynamic, shifting the old ones
// (and their DT_NULL) down, as patchelf does.
func (l *layout) prependDynamic(ents []dynNew) {
	ent := l.dynEntSize()
	n := uint64(len(ents))
	base := l.sh[l.must(".dynamic")].size
	if cur, ok := l.repl[".dynamic"]; ok {
		base = uint64(len(cur))
	}
	nb := l.replaceSection(".dynamic", base+n*ent)
	idx := -1
	for k := uint64(0); (k+1)*ent <= uint64(len(nb)); k++ {
		var tag uint64
		if l.is32() {
			tag = uint64(l.order.Uint32(nb[k*ent:]))
		} else {
			tag = l.order.Uint64(nb[k*ent:])
		}
		if tag == dtNull {
			idx = int(k)
			break
		}
	}
	if idx < 0 {
		l.bad(".dynamic section has no DT_NULL terminator")
	}
	copy(nb[n*ent:], nb[:uint64(idx+1)*ent])
	for k, e := range ents {
		at := uint64(k) * ent
		if l.is32() {
			l.order.PutUint32(nb[at:], uint32(e.tag))
		} else {
			l.order.PutUint64(nb[at:], uint64(e.tag))
		}
		l.ww(nb[at+l.word():], e.val)
	}
}

// putDynVal sets the value of the dynamic entry at file offset at in the image.
func (f *File) putDynVal(l *layout, at, v uint64) {
	l.ww(l.data[at+l.word():], v)
}

// zeroStr wipes an unshared old string, as patchelf wipes an old rpath, so a
// dropped path is not retained in the file.
func (f *File) zeroStr(o uint64, n int) {
	if n > 0 {
		f.write(f.strOff+o, make([]byte, n))
	}
}

func (f *File) needsDyn() error {
	if f.dynProg == nil {
		return ErrNoDynamic
	}
	return nil
}

// growInterpreter replaces .interp by a larger section.
func (f *File) growInterpreter(value string) error {
	return f.relayout([]string{".interp"}, func(l *layout) {
		s := l.replaceSection(".interp", uint64(len(value))+1)
		copy(s, value)
	})
}

// setStringTag points the dynamic entry i at a new string appended to .dynstr,
// wiping the old one when nothing else refers to it.
func (f *File) setStringTag(i int, value string, wipe bool, oldLen int) error {
	e := f.dyn[i]
	oldVal := e.val
	if wipe {
		f.zeroStr(oldVal, oldLen)
	}
	return f.relayout([]string{".dynstr"}, func(l *layout) {
		offs := l.appendStrings(".dynstr", []string{value})
		f.putDynVal(l, e.off, offs[0])
	})
}

// addStringTag adds a new dynamic entry (tag, value) at the top of .dynamic.
func (f *File) addStringTag(tag int64, value string) error {
	return f.relayout([]string{".dynstr", ".dynamic"}, func(l *layout) {
		offs := l.appendStrings(".dynstr", []string{value})
		l.prependDynamic([]dynNew{{tag, offs[0]}})
	})
}

// SetSoname sets DT_SONAME of a shared library, like patchelf --set-soname:
// executables are left alone (patchelf does nothing there either). The string
// is overwritten in place when it fits and nothing else points at it; otherwise
// it is appended to .dynstr, and a library with no DT_SONAME gets one at the
// top of .dynamic.
func (f *File) SetSoname(value string) ([]Change, error) {
	if hasNUL(value) {
		return nil, fmt.Errorf("elfpatch: invalid soname %q", value)
	}
	if f.Type != etDyn {
		return nil, nil
	}
	if err := f.needsDyn(); err != nil {
		return nil, err
	}
	i, has := f.firstDyn(dtSoname)
	if !has {
		if err := f.addStringTag(dtSoname, value); err != nil {
			return nil, fmt.Errorf("elfpatch: adding DT_SONAME: %w", err)
		}
		f.touched |= tSoname
		return []Change{{"soname", "", value}}, nil
	}
	old, err := f.strAt(f.dyn[i].val)
	if err != nil {
		return nil, err
	}
	if old == value {
		return nil, nil
	}
	skip := map[int]bool{i: true}
	shared, serr := f.refsInto(f.dyn[i].val, uint64(len(old)), skip)
	fits := len(value) <= len(old)
	if fits && serr != nil {
		return nil, serr
	}
	if fits && !shared {
		if err := f.writeSlot("soname", f.dyn[i].val, len(old), value, skip); err != nil {
			return nil, err
		}
	} else {
		if err := f.setStringTag(i, value, !shared && serr == nil, len(old)); err != nil {
			return nil, growErr("soname", uint64(len(old))+1, uint64(len(value))+1, len(value) <= len(old), err)
		}
	}
	f.touched |= tSoname
	if got, _, err := f.Soname(); err != nil || got != value {
		return nil, fmt.Errorf("%w: soname reads back %q", ErrVerify, got)
	}
	return []Change{{"soname", old, value}}, nil
}

// AddNeeded adds DT_NEEDED entries for libs, like patchelf --add-needed: the
// names are sorted and de-duplicated, appended to .dynstr, and the entries go
// at the TOP of .dynamic (so they are searched first). A name already needed
// is added again, as patchelf does.
func (f *File) AddNeeded(libs ...string) ([]Change, error) {
	set := slices.Clone(libs)
	slices.Sort(set)
	set = slices.Compact(set)
	for _, s := range set {
		if s == "" || hasNUL(s) {
			return nil, fmt.Errorf("elfpatch: invalid library name %q", s)
		}
	}
	if len(set) == 0 {
		return nil, nil
	}
	if err := f.needsDyn(); err != nil {
		return nil, err
	}
	err := f.relayout([]string{".dynstr", ".dynamic"}, func(l *layout) {
		offs := l.appendStrings(".dynstr", set)
		// patchelf's addNeeded reserves one byte more than the names need; the
		// same size keeps the layouts identical.
		l.replaceSection(".dynstr", uint64(len(l.repl[".dynstr"]))+1)
		ents := make([]dynNew, len(offs))
		for i, o := range offs {
			ents[i] = dynNew{dtNeeded, o}
		}
		l.prependDynamic(ents)
	})
	if err != nil {
		return nil, fmt.Errorf("elfpatch: adding DT_NEEDED: %w", err)
	}
	f.touched |= tNeeded
	cs := make([]Change, len(set))
	for i, s := range set {
		cs[i] = Change{"needed", "", s}
	}
	return cs, nil
}

// AddRpath appends dirs to the search path, like patchelf --add-rpath: the new
// value is "old:dirs" (or just dirs when there is none), and it is set as
// SetRpath sets it, so a file with no entry gets a DT_RUNPATH.
func (f *File) AddRpath(dirs string, force bool) ([]Change, error) {
	if err := f.needsDyn(); err != nil {
		return nil, err
	}
	cur, _, err := f.SearchPath()
	if err != nil {
		return nil, err
	}
	if cur != "" {
		cur += ":"
	}
	return f.SetRpath(cur+dirs, force)
}

// verneedFiles lists, for every Elf_Verneed, the file offset of vn_file and its
// dynstr offset.
func (f *File) verneedFiles() (at, val []uint64, err error) {
	v, ok := f.dynVal(dtVerneed)
	if !ok {
		return nil, nil, nil
	}
	num, _ := f.dynVal(dtVerneedN)
	off, ok := f.vaddrToOff(v)
	if !ok {
		return nil, nil, corrupt("DT_VERNEED %#x outside any PT_LOAD", v)
	}
	for i := uint64(0); i < num; i++ {
		if !inRange(off, 16, uint64(len(f.data))) {
			return nil, nil, corrupt("Verneed outside file")
		}
		file, _ := f.u32(off + 4)
		next, _ := f.u32(off + 12)
		at, val = append(at, off+4), append(val, uint64(file))
		if next == 0 {
			break
		}
		off += uint64(next)
	}
	return at, val, nil
}

// growReplace renames the DT_NEEDED entries at dyn indices idx (all named old)
// to new by appending to .dynstr, and renames the matching version-needed file
// names. It follows patchelf's replaceNeeded: a replacement that is a suffix of
// the old name just points into it; the same replacement is added once.
func (f *File) growReplace(old, new string, idx []int) error {
	vAt, vVal, err := f.verneedFiles()
	if err != nil {
		return err
	}
	var vIdx []int
	for k, v := range vVal {
		s, err := f.strAt(v)
		if err != nil {
			return err
		}
		if s == old {
			vIdx = append(vIdx, k)
		}
	}
	return f.relayout([]string{".dynstr"}, func(l *layout) {
		if len(vIdx) > 0 {
			vr := l.sh[l.must(".gnu.version_r")]
			if int(vr.link) != l.must(".dynstr") {
				l.fail("version-needed names live in %s, not .dynstr", l.secName(int(vr.link)))
			}
		}
		added := map[string]uint64{}
		for _, i := range idx {
			e := f.dyn[i]
			if a, ok := added[new]; ok {
				f.putDynVal(l, e.off, a)
				continue
			}
			if strings.HasSuffix(old, new) {
				f.putDynVal(l, e.off, e.val+uint64(len(old)-len(new)))
				continue
			}
			o := l.appendStrings(".dynstr", []string{new})[0]
			added[new] = o
			f.putDynVal(l, e.off, o)
		}
		for _, k := range vIdx {
			o, ok := added[new]
			if !ok {
				o = l.appendStrings(".dynstr", []string{new})[0]
				added[new] = o
			}
			l.order.PutUint32(l.data[vAt[k]:], uint32(o)) // vn_file is a u32; o < 2 GiB
		}
	})
}

// growable reports whether err is the kind of refusal growth can resolve.
func growable(err error) bool {
	return errors.Is(err, ErrNoSpace) || errors.Is(err, ErrAmbiguous)
}
