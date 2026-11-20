package elfpatch

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
)

// Options control Patch.
type Options struct {
	DryRun bool   // compute and verify the change, write nothing
	Output string // write here instead of replacing the input
	Sync   bool   // fsync the temp file before the rename (durability across a crash)
	// PageSize overrides the page size growth uses (patchelf --page-size);
	// 0 picks it from e_machine as patchelf does.
	PageSize uint64
}

type snapshot struct {
	interp                 string
	hasInterp              bool
	needed                 []string
	soname, rpath, runpath string
	hasSo, hasRp, hasRun   bool
}

func (f *File) snap() (s snapshot, err error) {
	if s.interp, s.hasInterp, err = f.Interpreter(); err != nil {
		return
	}
	if s.needed, err = f.Needed(); err != nil {
		return
	}
	if s.soname, s.hasSo, err = f.Soname(); err != nil {
		return
	}
	if s.rpath, s.hasRp, err = f.Rpath(); err != nil {
		return
	}
	s.runpath, s.hasRun, err = f.Runpath()
	return
}

// merged returns the declared ranges, sorted and coalesced.
func (f *File) merged() []rng {
	al := slices.Clone(f.allowed)
	slices.SortFunc(al, func(a, b rng) int {
		switch {
		case a.off < b.off:
			return -1
		case a.off > b.off:
			return 1
		}
		return 0
	})
	var out []rng
	for _, r := range al {
		if n := len(out); n > 0 && r.off <= out[n-1].end {
			out[n-1].end = max(out[n-1].end, r.end)
		} else {
			out = append(out, r)
		}
	}
	return out
}

// verify judges an edit from three byte images: orig (the input), out (the
// output, re-parsed here) and f (the editor, which knows what it declared and
// what it meant to write). It requires that
//
//   - out parses, and has the length of orig;
//   - out equals orig everywhere outside the declared ranges;
//   - out equals the editor's bytes inside them;
//   - every field the edit did not claim to touch reads back unchanged.
//
// Anything else is ErrVerify and nothing is written.
func verify(orig, out []byte, f *File) error {
	if len(orig) != len(out) {
		return fmt.Errorf("%w: length changed", ErrVerify)
	}
	o, err := Parse(orig)
	if err != nil {
		return err
	}
	g, err := Parse(out)
	if err != nil {
		return fmt.Errorf("%w: output does not parse: %v", ErrVerify, err)
	}
	pos := uint64(0)
	for _, r := range f.merged() {
		if r.end > uint64(len(orig)) || len(f.data) != len(orig) {
			return fmt.Errorf("%w: declared range outside file", ErrVerify)
		}
		if r.off > pos && !bytes.Equal(orig[pos:r.off], out[pos:r.off]) {
			return fmt.Errorf("%w: bytes changed outside the targeted field near offset %d", ErrVerify, pos)
		}
		if !bytes.Equal(out[r.off:r.end], f.data[r.off:r.end]) {
			return fmt.Errorf("%w: written bytes differ from the intended edit at offset %d", ErrVerify, r.off)
		}
		pos = r.end
	}
	if !bytes.Equal(orig[pos:], out[pos:]) {
		return fmt.Errorf("%w: bytes changed outside the targeted field after offset %d", ErrVerify, pos)
	}
	return compareSnaps(o, g, f.touched)
}

// compareSnaps requires every field the edit did not claim to touch to read
// back unchanged, and the identity of the file (class, machine, type) to stay.
func compareSnaps(o, g *File, t touched) error {
	so, err := o.snap()
	if err != nil {
		return err
	}
	sg, err := g.snap()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVerify, err)
	}
	bad := func(field string) error { return fmt.Errorf("%w: untouched field %s changed", ErrVerify, field) }
	switch {
	case t&tInterp == 0 && (so.interp != sg.interp || so.hasInterp != sg.hasInterp):
		return bad("interpreter")
	case t&tNeeded == 0 && !slices.Equal(so.needed, sg.needed):
		return bad("needed")
	case t&tSoname == 0 && (so.soname != sg.soname || so.hasSo != sg.hasSo):
		return bad("soname")
	case t&(tRpath|tRunpath) == 0 && (so.rpath != sg.rpath || so.hasRp != sg.hasRp || so.runpath != sg.runpath || so.hasRun != sg.hasRun):
		return bad("rpath/runpath")
	}
	if o.Class != g.Class || o.Machine != g.Machine || o.Type != g.Type {
		return bad("header")
	}
	return nil
}

// guard turns the fault of a mapped file that was truncated under us into an
// error instead of a crash. Other panics are not ours to hide.
func guard(fn func() error) (err error) {
	old := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(old)
	defer func() {
		if r := recover(); r != nil {
			if re, ok := r.(runtime.Error); ok && strings.Contains(re.Error(), "fault") {
				err = fmt.Errorf("elfpatch: the file changed while it was mapped: %v", re)
				return
			}
			panic(r)
		}
	}()
	return fn()
}

func openRegular(path string) (*os.File, int, os.FileInfo, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, 0, nil, err
	}
	switch {
	case !st.Mode().IsRegular():
		return nil, 0, nil, fmt.Errorf("elfpatch: %s is not a regular file", path)
	case uint64(st.Size()) > maxFile:
		return nil, 0, nil, fmt.Errorf("%w: %s is larger than the %d-byte limit", ErrUnsupported, path, maxFile)
	case st.Size() == 0:
		return nil, 0, nil, fmt.Errorf("%w: %s is empty", ErrNotELF, path)
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, 0, nil, err
	}
	return fh, int(st.Size()), st, nil
}

// mapFile is replaceable in tests, which cannot otherwise make a map fail.
var mapFile = sysMap

// Open maps path read-only and parses it. Only the pages the parser touches
// are read, so a print costs the same on a 32 MiB binary as on a 16 KiB one.
// Close the File when done; it must not be used afterwards.
func Open(path string) (f *File, err error) {
	err = guard(func() error {
		fh, size, _, err := openRegular(path)
		if err != nil {
			return err
		}
		defer fh.Close()
		data, unmap, err := mapFile(fh, size, false)
		if err != nil {
			return err
		}
		f, err = Parse(data)
		if err != nil {
			unmap()
			return err
		}
		f.closer = unmap
		return nil
	})
	if err != nil {
		f = nil
	}
	return f, err
}

// Close releases the mapping of a File from Open. It is a no-op for Parse.
func (f *File) Close() error {
	if f.closer == nil {
		return nil
	}
	c := f.closer
	f.closer, f.data = nil, nil
	return c()
}

// Patch maps path, runs fn on a copy-on-write view, and (unless DryRun)
// replaces the file atomically: a temp file in the same directory is created
// from the original (copy_file_range where the kernel has it), only the edited
// ranges are written into it, the original mode is applied, the temp file is
// RE-PARSED and verified against the input, and only then renamed over it.
// A symlink is followed so the target is replaced and the link survives. On
// any error nothing is written and no temp file is left behind.
func Patch(path string, opts Options, fn func(*File) ([]Change, error)) (cs []Change, err error) {
	err = guard(func() error {
		var err error
		cs, err = patch(path, opts, fn)
		return err
	})
	if err != nil {
		cs = nil
	}
	return cs, err
}

func patch(path string, opts Options, fn func(*File) ([]Change, error)) ([]Change, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	src, size, st, err := openRegular(real)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	orig, unmapO, err := mapFile(src, size, false)
	if err != nil {
		return nil, err
	}
	defer unmapO()
	work, unmapW, err := mapFile(src, size, true)
	if err != nil {
		return nil, err
	}
	defer unmapW()

	f, err := Parse(work)
	if err != nil {
		return nil, err
	}
	// A file whose untouched fields cannot even be read is not edited: the
	// verifier could not tell us the edit left them alone.
	if _, err := f.snap(); err != nil {
		return nil, err
	}
	f.forcedPage = opts.PageSize
	cs, err := fn(f)
	if err != nil {
		return nil, err
	}
	if len(cs) == 0 {
		return nil, nil
	}
	if f.grown {
		if opts.DryRun {
			return cs, verifyGrown(orig, f.data, f)
		}
		dest := real
		if opts.Output != "" {
			dest = opts.Output
		}
		return cs, writeGrown(dest, st.Mode(), orig, f, opts.Sync)
	}
	if opts.DryRun {
		return cs, verify(orig, work, f)
	}
	dest := real
	if opts.Output != "" {
		dest = opts.Output
	}
	return cs, writeVerified(dest, src, size, st.Mode(), orig, f, opts.Sync)
}

// writeGrown writes a grown image: the whole new content into a temp file in
// the destination's directory, then the same checks as writeVerified on the
// bytes as they landed (they must equal the editor's image, and that image must
// pass verifyGrown against the input), and only then the rename.
func writeGrown(dest string, mode os.FileMode, orig []byte, f *File, sync bool) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".elfpatch-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(name)
		}
	}()
	if n, err := tmp.Write(f.data); err != nil || n != len(f.data) {
		return fmt.Errorf("elfpatch: writing %s: %d of %d bytes: %v", name, n, len(f.data), err)
	}
	if err := tmp.Chmod(mode & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)); err != nil {
		return err
	}
	if sync {
		if err := tmp.Sync(); err != nil {
			return err
		}
	}
	out, unmap, err := mapFile(tmp, len(f.data), false)
	if err != nil {
		return err
	}
	err = verifyGrown(orig, out, f) // the file as written, not as intended
	unmap()
	if err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, dest)
}

func writeVerified(dest string, src *os.File, size int, mode os.FileMode, orig []byte, f *File, sync bool) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".elfpatch-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(name)
		}
	}()
	if n, err := tmp.ReadFrom(src); err != nil || n != int64(size) {
		return fmt.Errorf("elfpatch: copying %s: %d of %d bytes: %v", src.Name(), n, size, err)
	}
	for _, r := range f.merged() {
		if _, err := tmp.WriteAt(f.data[r.off:r.end], int64(r.off)); err != nil {
			return err
		}
	}
	if err := tmp.Chmod(mode & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)); err != nil {
		return err
	}
	if sync {
		if err := tmp.Sync(); err != nil {
			return err
		}
	}
	out, unmap, err := mapFile(tmp, size, false)
	if err != nil {
		return err
	}
	err = verify(orig, out, f) // the file as written, not as intended
	unmap()
	if err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, dest)
}

// Path-level conveniences.

func SetInterpreter(path, value string, o Options) ([]Change, error) {
	return Patch(path, o, func(f *File) ([]Change, error) { return f.SetInterpreter(value) })
}

func SetRpath(path, value string, force bool, o Options) ([]Change, error) {
	return Patch(path, o, func(f *File) ([]Change, error) { return f.SetRpath(value, force) })
}

func RemoveRpath(path string, o Options) ([]Change, error) {
	return Patch(path, o, func(f *File) ([]Change, error) { return f.RemoveRpath() })
}

func RemoveNeeded(path, name string, o Options) ([]Change, error) {
	return Patch(path, o, func(f *File) ([]Change, error) { return f.RemoveNeeded(name) })
}

func ReplaceNeeded(path, old, new string, o Options) ([]Change, error) {
	return Patch(path, o, func(f *File) ([]Change, error) { return f.ReplaceNeeded(old, new) })
}

func ShrinkRpath(path string, o Options) ([]Change, error) {
	return Patch(path, o, func(f *File) ([]Change, error) { return f.ShrinkRpath(OriginDir(path)) })
}

// OriginDir is the directory $ORIGIN expands to for the file at path: the
// directory of the file after following symlinks, as the dynamic loader does.
func OriginDir(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Dir(path)
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		abs = r
	}
	return filepath.Dir(abs)
}
