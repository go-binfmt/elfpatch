package elfpatch

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Change describes one edit, for --dry-run and for callers' logs.
type Change struct {
	Field string // "interpreter", "rpath", "runpath", "needed", "tag"
	Old   string
	New   string
}

func (c Change) String() string {
	return fmt.Sprintf("%s: %q -> %q", c.Field, c.Old, c.New)
}

// write is the only way an edit changes the image: it declares the range and
// writes it, so the verifier knows exactly what was meant to change.
func (f *File) write(off uint64, b []byte) {
	if len(b) == 0 {
		return
	}
	f.allowed = append(f.allowed, rng{off, off + uint64(len(b))})
	if inRange(off, uint64(len(b)), uint64(len(f.data))) {
		copy(f.data[off:], b)
	}
}

func hasNUL(s string) bool { return strings.IndexByte(s, 0) >= 0 }

// SetInterpreter overwrites PT_INTERP in place, zero-padding the slot. It
// returns a *NoSpaceError (ErrNoSpace) when value+NUL exceeds p_filesz.
func (f *File) SetInterpreter(value string) ([]Change, error) {
	p := f.interp
	if p == nil {
		return nil, ErrNoInterp
	}
	if value == "" || hasNUL(value) {
		return nil, fmt.Errorf("elfpatch: invalid interpreter %q", value)
	}
	old, _, err := f.Interpreter()
	if err != nil {
		return nil, err
	}
	if need := uint64(len(value)) + 1; need > p.filesz {
		return nil, &NoSpaceError{Field: "interpreter", Have: p.filesz, Need: need}
	}
	if old == value {
		return nil, nil
	}
	buf := make([]byte, p.filesz)
	copy(buf, value)
	f.write(p.off, buf)
	f.touched |= tInterp
	if got, _, err := f.Interpreter(); err != nil || got != value {
		return nil, fmt.Errorf("%w: interpreter reads back %q", ErrVerify, got)
	}
	return []Change{{"interpreter", old, value}}, nil
}

// refsInto reports whether any dynstr reference other than the dynamic
// entries in skip points into [start, start+n) of .dynstr. Linkers merge
// string tails, so zero-padding a slot that another name points into would
// corrupt that name. Checked: dynamic string tags, .dynsym names (count from
// DT_HASH or DT_GNU_HASH), version needs and definitions.
func (f *File) refsInto(start, n uint64, skip map[int]bool) (bool, error) {
	hit := func(r uint64) bool { return r >= start && r-start < n }
	for i, e := range f.dyn {
		switch e.tag {
		case dtNeeded, dtSoname, dtRpath, dtRunpath, 0x7ffffffd, 0x7fffffff:
			if !skip[i] && hit(e.val) {
				return true, nil
			}
		}
	}
	var found bool
	err := f.eachForeignName(func(r uint64) { found = found || hit(r) })
	return found, err
}

func (f *File) u32(off uint64) (uint32, bool) {
	if !inRange(off, 4, uint64(len(f.data))) {
		return 0, false
	}
	return f.Order.Uint32(f.data[off:]), true
}

func (f *File) dynVal(tag int64) (uint64, bool) {
	if i, ok := f.firstDyn(tag); ok {
		return f.dyn[i].val, true
	}
	return 0, false
}

// eachForeignName calls fn with every dynstr offset referenced by .dynsym,
// version needs and version definitions.
func (f *File) eachForeignName(fn func(uint64)) error {
	if sym, ok := f.dynVal(dtSymtab); ok {
		so, ok := f.vaddrToOff(sym)
		if !ok {
			return corrupt("DT_SYMTAB %#x outside any PT_LOAD", sym)
		}
		ent := uint64(24)
		if f.Class == 32 {
			ent = 16
		}
		count, err := f.symCount(sym)
		if err != nil {
			return err
		}
		if !inRange(so, count*ent, uint64(len(f.data))) {
			return corrupt(".dynsym of %d entries outside file", count)
		}
		for i := uint64(0); i < count; i++ {
			fn(uint64(f.Order.Uint32(f.data[so+i*ent:])))
		}
	}
	if v, ok := f.dynVal(dtVerneed); ok {
		num, _ := f.dynVal(dtVerneedN)
		if err := f.walkVer(v, num, fn); err != nil {
			return err
		}
	}
	if v, ok := f.dynVal(dtVerdef); ok {
		num, _ := f.dynVal(dtVerdefN)
		if err := f.walkDef(v, num, fn); err != nil {
			return err
		}
	}
	return nil
}

// walkVer walks DT_VERNEED: Elf_Verneed {vn_version u16, vn_cnt u16,
// vn_file u32, vn_aux u32, vn_next u32} then Elf_Vernaux {vna_hash u32,
// vna_flags u16, vna_other u16, vna_name u32, vna_next u32}.
func (f *File) walkVer(vaddr, num uint64, fn func(uint64)) error {
	const fileAt, auxAt, nextAt, nameAt, vnaNext = 4, 8, 12, 8, 12
	off, ok := f.vaddrToOff(vaddr)
	if !ok {
		return corrupt("DT_VERNEED %#x outside any PT_LOAD", vaddr)
	}
	steps := uint64(0)
	for i := uint64(0); i < num; i++ {
		if steps++; steps > uint64(len(f.data)) {
			return corrupt("version-needed chain loops")
		}
		if !inRange(off, 16, uint64(len(f.data))) {
			return corrupt("Verneed outside file")
		}
		cnt := uint64(f.Order.Uint16(f.data[off+2:]))
		file, _ := f.u32(off + fileAt)
		fn(uint64(file))
		aux, _ := f.u32(off + auxAt)
		next, _ := f.u32(off + nextAt)
		ao := off + uint64(aux)
		for j := uint64(0); j < cnt; j++ {
			if !inRange(ao, 16, uint64(len(f.data))) {
				return corrupt("Vernaux outside file")
			}
			name, _ := f.u32(ao + nameAt)
			fn(uint64(name))
			an, _ := f.u32(ao + vnaNext)
			if an == 0 {
				break
			}
			ao += uint64(an)
		}
		if next == 0 {
			break
		}
		off += uint64(next)
	}
	return nil
}

// walkDef walks DT_VERDEF: Elf_Verdef {vd_version u16, vd_flags u16,
// vd_ndx u16, vd_cnt u16, vd_hash u32, vd_aux u32, vd_next u32} then
// Elf_Verdaux {vda_name u32, vda_next u32}.
func (f *File) walkDef(vaddr, num uint64, fn func(uint64)) error {
	off, ok := f.vaddrToOff(vaddr)
	if !ok {
		return corrupt("DT_VERDEF %#x outside any PT_LOAD", vaddr)
	}
	for i := uint64(0); i < num; i++ {
		if !inRange(off, 20, uint64(len(f.data))) {
			return corrupt("Verdef outside file")
		}
		cnt := uint64(f.Order.Uint16(f.data[off+6:]))
		aux, _ := f.u32(off + 12)
		next, _ := f.u32(off + 16)
		ao := off + uint64(aux)
		for j := uint64(0); j < cnt; j++ {
			if !inRange(ao, 8, uint64(len(f.data))) {
				return corrupt("Verdaux outside file")
			}
			name, _ := f.u32(ao)
			fn(uint64(name))
			an, _ := f.u32(ao + 4)
			if an == 0 {
				break
			}
			ao += uint64(an)
		}
		if next == 0 {
			break
		}
		off += uint64(next)
	}
	return nil
}

// symCount sizes .dynsym: DT_HASH's nchain, else DT_GNU_HASH's highest chain,
// else the gap up to .dynstr when that follows the table.
func (f *File) symCount(symVaddr uint64) (uint64, error) {
	if h, ok := f.dynVal(dtHash); ok {
		off, ok := f.vaddrToOff(h)
		if !ok {
			return 0, corrupt("DT_HASH outside any PT_LOAD")
		}
		n, ok := f.u32(off + 4)
		if !ok {
			return 0, corrupt("DT_HASH outside file")
		}
		return uint64(n), nil
	}
	if h, ok := f.dynVal(dtGnuHash); ok {
		off, ok := f.vaddrToOff(h)
		if !ok {
			return 0, corrupt("DT_GNU_HASH outside any PT_LOAD")
		}
		nb, ok1 := f.u32(off)
		symoff, ok2 := f.u32(off + 4)
		bloom, ok3 := f.u32(off + 8)
		if !ok1 || !ok2 || !ok3 {
			return 0, corrupt("DT_GNU_HASH outside file")
		}
		w := uint64(f.Class / 8)
		buckets := off + 16 + uint64(bloom)*w
		chains := buckets + uint64(nb)*4
		var maxSym uint32
		for i := uint64(0); i < uint64(nb); i++ {
			b, ok := f.u32(buckets + i*4)
			if !ok {
				return 0, corrupt("DT_GNU_HASH buckets outside file")
			}
			maxSym = max(maxSym, b)
		}
		if maxSym < symoff {
			return uint64(symoff), nil
		}
		idx := uint64(maxSym)
		for {
			c, ok := f.u32(chains + (idx-uint64(symoff))*4)
			if !ok {
				return 0, corrupt("DT_GNU_HASH chain outside file")
			}
			idx++
			if c&1 == 1 {
				return idx, nil
			}
		}
	}
	if st, ok := f.dynVal(dtStrtab); ok && st > symVaddr {
		ent := uint64(24)
		if f.Class == 32 {
			ent = 16
		}
		return (st - symVaddr) / ent, nil
	}
	return 0, fmt.Errorf("%w: cannot size .dynsym to prove no name shares the string", ErrAmbiguous)
}

// writeSlot overwrites the dynstr string at rel offset o (currently oldLen
// bytes) with value, zero-padding to the old length. skip names the dynamic
// entries that legitimately point at it.
func (f *File) writeSlot(field string, o uint64, oldLen int, value string, skip map[int]bool) error {
	if uint64(len(value)) > uint64(oldLen) {
		return &NoSpaceError{Field: field, Have: uint64(oldLen) + 1, Need: uint64(len(value)) + 1}
	}
	shared, err := f.refsInto(o, uint64(oldLen), skip)
	if err != nil {
		return err
	}
	if shared {
		return fmt.Errorf("%w: another name points into the %s string", ErrAmbiguous, field)
	}
	buf := make([]byte, oldLen)
	copy(buf, value)
	f.write(f.strOff+o, buf)
	return nil
}

func (f *File) setTag(i int, tag int64) {
	e := f.dyn[i]
	var b [8]byte
	if f.Class == 32 {
		f.Order.PutUint32(b[:], uint32(tag))
		f.write(e.off, b[:4])
	} else {
		f.Order.PutUint64(b[:], uint64(tag))
		f.write(e.off, b[:8])
	}
	f.dyn[i].tag = tag
}

// removeDyn deletes dynamic entry i by shifting the later ones down and
// zero-filling (DT_NULL) the freed tail slot, as patchelf does.
func (f *File) removeDyn(i int) error {
	n := len(f.dyn)
	start := f.dyn[i].off
	end := f.dynProg.off + uint64(n)*f.entSize
	shifted := make([]byte, end-start) // the later entries, one slot down; the last slot zero
	copy(shifted, f.data[start+f.entSize:end])
	f.write(start, shifted)
	return f.loadDynamic()
}

// SetRpath sets the search path in place. Like patchelf it writes DT_RUNPATH
// (converting a DT_RPATH tag), or keeps/creates DT_RPATH when force is true.
// An empty value leaves an empty entry, as patchelf --set-rpath "" does (use
// RemoveRpath to delete it). With no entry to edit it returns ErrNoRpath
// (adding one needs growth: phase 2).
func (f *File) SetRpath(value string, force bool) ([]Change, error) {
	if f.dynProg == nil {
		return nil, ErrNoDynamic
	}
	if hasNUL(value) {
		return nil, fmt.Errorf("elfpatch: invalid rpath %q", value)
	}
	ri, hasRun := f.firstDyn(dtRunpath)
	pi, hasRp := f.firstDyn(dtRpath)
	if hasRun && hasRp {
		return nil, fmt.Errorf("%w: both DT_RPATH and DT_RUNPATH are present", ErrAmbiguous)
	}
	if !hasRun && !hasRp {
		return nil, ErrNoRpath
	}
	idx, field := ri, "runpath"
	if hasRp {
		idx, field = pi, "rpath"
	}
	old, err := f.strAt(f.dyn[idx].val)
	if err != nil {
		return nil, err
	}
	want := int64(dtRunpath)
	if force {
		want = dtRpath
	}
	if old == value && f.dyn[idx].tag == want {
		return nil, nil
	}
	if err := f.writeSlot(field, f.dyn[idx].val, len(old), value, map[int]bool{idx: true}); err != nil {
		return nil, err
	}
	var cs []Change
	if f.dyn[idx].tag != want {
		from := f.dyn[idx].tag
		f.setTag(idx, want)
		cs = append(cs, Change{"tag", tagName(from), tagName(want)})
	}
	f.touched |= tRpath | tRunpath
	got, _, err := f.SearchPath()
	if err != nil || got != value {
		return nil, fmt.Errorf("%w: search path reads back %q", ErrVerify, got)
	}
	if old != value {
		cs = append(cs, Change{field, old, value})
	}
	return cs, nil
}

// RemoveRpath deletes the DT_RPATH/DT_RUNPATH entry (patchelf --remove-rpath)
// by shifting the later dynamic entries down. No entry is not an error.
func (f *File) RemoveRpath() ([]Change, error) {
	var cs []Change
	for {
		idx, ok := f.firstDyn(dtRunpath, dtRpath)
		if !ok {
			return cs, nil
		}
		old, err := f.strAt(f.dyn[idx].val)
		if err != nil {
			return nil, err
		}
		field := "runpath"
		if f.dyn[idx].tag == dtRpath {
			field = "rpath"
		}
		if err := f.removeDyn(idx); err != nil {
			return nil, err
		}
		f.touched |= tRpath | tRunpath
		cs = append(cs, Change{field, old, ""})
	}
}

func tagName(t int64) string {
	switch t {
	case dtRpath:
		return "DT_RPATH"
	case dtRunpath:
		return "DT_RUNPATH"
	}
	return fmt.Sprint(t)
}

// RemoveNeeded deletes every DT_NEEDED entry named name. No match is not an
// error (patchelf agrees): the result is empty.
func (f *File) RemoveNeeded(name string) ([]Change, error) {
	var cs []Change
	for {
		idx := -1
		for i, e := range f.dyn {
			if e.tag != dtNeeded {
				continue
			}
			s, err := f.strAt(e.val)
			if err != nil {
				return nil, err
			}
			if s == name {
				idx = i
				break
			}
		}
		if idx < 0 {
			break
		}
		if err := f.removeDyn(idx); err != nil {
			return nil, err
		}
		f.touched |= tNeeded
		cs = append(cs, Change{"needed", name, ""})
	}
	return cs, nil
}

// ReplaceNeeded renames every DT_NEEDED entry old to new in place.
func (f *File) ReplaceNeeded(old, new string) ([]Change, error) {
	if new == "" || hasNUL(new) {
		return nil, fmt.Errorf("elfpatch: invalid library name %q", new)
	}
	done := map[uint64]bool{}
	var cs []Change
	for _, e := range f.dyn {
		if e.tag != dtNeeded || done[e.val] {
			continue
		}
		s, err := f.strAt(e.val)
		if err != nil {
			return nil, err
		}
		if s != old || old == new {
			continue
		}
		skip := map[int]bool{}
		for j, e2 := range f.dyn {
			if e2.tag == dtNeeded && e2.val == e.val {
				skip[j] = true
			}
		}
		if err := f.writeSlot("needed", e.val, len(s), new, skip); err != nil {
			return nil, err
		}
		done[e.val] = true
		f.touched |= tNeeded
		cs = append(cs, Change{"needed", old, new})
	}
	return cs, nil
}

// ShrinkRpath removes search-path directories that provide none of the
// DT_NEEDED libraries (and duplicates), like patchelf --shrink-rpath. origin
// is the directory $ORIGIN expands to (the file's own directory). A library
// counts as provided by a directory when a same-class, same-machine ELF of
// that name is there; each needed library is assigned to the first directory
// that provides it. Entries it cannot judge ($LIB, $PLATFORM) are kept.
func (f *File) ShrinkRpath(origin string) ([]Change, error) {
	cur, ok, err := f.SearchPath()
	if err != nil || !ok || cur == "" {
		return nil, err
	}
	needed, err := f.Needed()
	if err != nil {
		return nil, err
	}
	dirs := strings.Split(cur, ":")
	used := make([]bool, len(dirs))
	for _, lib := range needed {
		if strings.Contains(lib, "/") {
			continue
		}
		for i, d := range dirs {
			if d == "" || strings.Contains(d, "$LIB") || strings.Contains(d, "${LIB}") ||
				strings.Contains(d, "$PLATFORM") || strings.Contains(d, "${PLATFORM}") {
				continue
			}
			d = strings.ReplaceAll(strings.ReplaceAll(d, "${ORIGIN}", origin), "$ORIGIN", origin)
			if f.providesLib(filepath.Join(d, lib)) {
				used[i] = true
				break
			}
		}
	}
	var keep []string
	for i, d := range dirs {
		if d == "" || strings.Contains(d, "$LIB") || strings.Contains(d, "${LIB}") ||
			strings.Contains(d, "$PLATFORM") || strings.Contains(d, "${PLATFORM}") {
			// unjudgeable (or empty): empty means "cwd" to the loader, so keep it too
			used[i] = true
		}
		if used[i] && !slices.Contains(keep, d) {
			keep = append(keep, d)
		}
	}
	return f.SetRpath(strings.Join(keep, ":"), false)
}

// providesLib reports whether path is an ELF of the same class and machine.
func (f *File) providesLib(path string) bool {
	fh, err := os.Open(path)
	if err != nil {
		return false
	}
	defer fh.Close()
	var h [20]byte
	if _, err := fh.ReadAt(h[:], 0); err != nil || string(h[:4]) != "\x7fELF" {
		return false
	}
	return int(h[4])*32 == f.Class && h[5] == f.data[5] && f.Order.Uint16(h[18:]) == f.Machine
}
