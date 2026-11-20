package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-binfmt/elfpatch/internal/elfgen"
)

func layoutFixture(t *testing.T, exec bool) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "prog")
	img := elfgen.BuildLayout(elfgen.LSpec{
		Exec: exec, Interp: "/lib/ld.so.1", Needed: []string{"libm.so.6"}, Soname: "libp.so", Rpath: "/a",
		Symbols: []string{"main"}, Notes: true,
	})
	if err := os.WriteFile(p, img, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGrowthFlags(t *testing.T) {
	long := "/" + strings.Repeat("z", 300)
	for _, exec := range []bool{true, false} {
		p := layoutFixture(t, exec)
		if _, _, err := do(t, "--set-interpreter", long, "--add-rpath", "/b", "--add-needed", "libz.so.1", "--add-needed", "liba.so.1",
			"--set-soname", "libnew-"+long, "--replace-needed", "libm.so.6", "libm-"+long, "--page-size", "8192", p); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct{ flag, want string }{
			{"--print-interpreter", long + "\n"},
			{"--print-rpath", "/a:/b\n"},
			{"--print-needed", "liba.so.1\nlibz.so.1\nlibm-" + long + "\n"},
		} {
			if out, _, err := do(t, tc.flag, p); err != nil || out != tc.want {
				t.Fatalf("exec=%v %s: %q %v", exec, tc.flag, out, err)
			}
		}
		want := "libnew-" + long + "\n"
		if !exec {
			if out, _, err := do(t, "--print-soname", p); err != nil || out != want {
				t.Fatalf("soname %q %v", out, err)
			}
		} else if out, _, err := do(t, "--print-soname", p); err != nil || out != "" {
			// patchelf prints nothing for a file that is not a shared object
			t.Fatalf("an executable's soname: %q %v", out, err)
		}
	}
	// --dry-run prints the growth and writes nothing
	p := layoutFixture(t, true)
	before, _ := os.ReadFile(p)
	out, _, err := do(t, "--dry-run", "--set-rpath", long, p)
	if err != nil || !strings.Contains(out, "runpath") {
		t.Fatal(out, err)
	}
	if after, _ := os.ReadFile(p); string(after) != string(before) {
		t.Fatal("dry run wrote")
	}
}
