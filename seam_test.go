package elfpatch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/go-zpkg/elfpatch/internal/elfgen"
)

var errBoom = errors.New("map boom")

// breakMap makes the nth call of mapFile fail (garble=false) or return a
// zeroed image of the right size (garble=true), and restores it afterwards.
func breakMap(t *testing.T, n int, garble bool) {
	t.Helper()
	real, calls := mapFile, 0
	mapFile = func(fh *os.File, size int, write bool) ([]byte, func() error, error) {
		calls++
		if calls != n {
			return real(fh, size, write)
		}
		if garble {
			return make([]byte, size), func() error { return nil }, nil
		}
		return nil, nil, errBoom
	}
	t.Cleanup(func() { mapFile = real })
}

func untouched(t *testing.T, p string, want []byte) {
	t.Helper()
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, want) {
		t.Fatal("the target changed")
	}
	ents, _ := os.ReadDir(filepath.Dir(p))
	if len(ents) != 1 {
		t.Fatalf("temp file left behind: %v", ents)
	}
}

func TestPatchWhenAMapFails(t *testing.T) {
	// 1: the read-only view, 2: the copy-on-write view, 3: the temp file's view.
	// (Open/Patch map once or twice before the temp file is made.)
	for n := 1; n <= 3; n++ {
		img := elfgen.Build(spec(variants[0]))
		p := write(t, img)
		breakMap(t, n, false)
		if _, err := SetRpath(p, "/q", false, Options{}); !errors.Is(err, errBoom) {
			t.Fatalf("map %d: %v", n, err)
		}
		untouched(t, p, img)
		mapFile = sysMap
	}
}

func TestPatchRefusesAnOutputThatIsNotWhatWasMeant(t *testing.T) {
	img := elfgen.Build(spec(variants[0]))
	p := write(t, img)
	breakMap(t, 3, true) // the view of the file as written reads back as zeros
	_, err := SetRpath(p, "/q", false, Options{})
	wantMsg(t, err, ErrVerify, "does not parse")
	untouched(t, p, img)
}

func TestOpenWhenTheMapFails(t *testing.T) {
	p := write(t, elfgen.Build(spec(variants[0])))
	breakMap(t, 1, false)
	if f, err := Open(p); !errors.Is(err, errBoom) || f != nil {
		t.Fatal(f, err)
	}
}

func TestFileSizeLimit(t *testing.T) {
	old := maxFile
	defer func() { maxFile = old }()
	img := elfgen.Build(spec(variants[0]))
	maxFile = uint64(len(img)) - 1
	if _, err := Parse(img); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	p := write(t, img)
	if _, err := Open(p); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := SetRpath(p, "/q", false, Options{}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	maxFile = uint64(len(img)) // exactly at the limit is fine
	if _, err := Parse(img); err != nil {
		t.Fatal(err)
	}
}

func TestPathErrorsSayWhy(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	_, err := SetRpath(missing, "/q", false, Options{})
	wantMsg(t, err, fs.ErrNotExist, "missing")
	_, err = SetRpath(dir, "/q", false, Options{})
	wantMsg(t, err, nil, "not a regular file")
	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, nil, 0o644)
	_, err = SetRpath(empty, "/q", false, Options{})
	wantMsg(t, err, ErrNotELF, "empty")

	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		return
	}
	locked := write(t, elfgen.Build(spec(variants[0])))
	os.Chmod(locked, 0)
	defer os.Chmod(locked, 0o644)
	if _, err := Open(locked); !errors.Is(err, fs.ErrPermission) {
		t.Fatal(err)
	}
	if _, err := SetRpath(locked, "/q", false, Options{}); !errors.Is(err, fs.ErrPermission) {
		t.Fatal(err)
	}
}

func TestNoProgramHeaders(t *testing.T) {
	b := elfgen.Build(spec(variants[0]))
	binary.LittleEndian.PutUint16(b[54:], 0) // e_phentsize
	binary.LittleEndian.PutUint16(b[56:], 0) // e_phnum
	f, err := Parse(b)
	if err != nil {
		t.Fatalf("an ELF with no program headers (phentsize 0) must parse: %v", err)
	}
	if _, ok, _ := f.Interpreter(); ok {
		t.Fatal("interpreter")
	}
}

func TestNoDynamicSegment(t *testing.T) {
	b := elfgen.Build(spec(variants[0]))
	f := mustParse(t, slices.Clone(b))
	binary.LittleEndian.PutUint32(b[f.dynProg.hdrOff:], 0) // PT_DYNAMIC -> PT_NULL
	g, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := g.Needed(); err != nil || len(n) != 0 {
		t.Fatal(n, err)
	}
	if _, err := g.SetRpath("/q", false); !errors.Is(err, ErrNoDynamic) {
		t.Fatal(err)
	}
	if s, ok, err := g.Interpreter(); err != nil || !ok || !strings.HasPrefix(s, "/lib64") {
		t.Fatal(s, ok, err)
	}
}
