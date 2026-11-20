// Command mkcorpus writes the committed fuzz seeds (testdata/fuzz/FuzzParse and
// testdata/fuzz/FuzzGrow)
// and fixture images (testdata/*.elf) from internal/elfgen. Run from the
// repository root: go run ./internal/mkcorpus
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-binfmt/elfpatch/internal/elfgen"
)

func main() {
	if err := run("testdata"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(dir string) error {
	corpus := filepath.Join(dir, "fuzz", "FuzzParse")
	if err := os.MkdirAll(corpus, 0o755); err != nil {
		return err
	}
	for _, class := range []int{32, 64} {
		for _, big := range []bool{false, true} {
			end := "le"
			if big {
				end = "be"
			}
			base := elfgen.Spec{
				Class: class, BigEndian: big, Interp: "/lib/ld.so.1", InterpSlot: 32,
				Needed: []string{"libc.so.6", "libm.so.6"}, Soname: "libx.so.1",
				Rpath: "/opt/placeholder/aaaaaaaaaaaaaaaa", RpathSlot: 48, Symbols: []string{"main", "puts"},
			}
			shared := base
			shared.TailNeeded, shared.TailSymbol = 5, 5
			rp := base
			rp.RpathTag = 15
			for name, s := range map[string]elfgen.Spec{"runpath": base, "tail": shared, "rpath": rp} {
				img := elfgen.Build(s)
				stem := fmt.Sprintf("%s-%d%s", name, class, end)
				if err := os.WriteFile(filepath.Join(dir, stem+".elf"), img, 0o644); err != nil {
					return err
				}
				seed := fmt.Sprintf("go test fuzz v1\n[]byte(%q)\n", img)
				if err := os.WriteFile(filepath.Join(corpus, stem), []byte(seed), 0o644); err != nil {
					return err
				}
			}
		}
	}
	grow := filepath.Join(dir, "fuzz", "FuzzGrow")
	if err := os.MkdirAll(grow, 0o755); err != nil {
		return err
	}
	for i, s := range elfgen.GrowSeeds() {
		img := elfgen.BuildLayout(s)
		seed := fmt.Sprintf("go test fuzz v1\n[]byte(%q)\n", img)
		name := fmt.Sprintf("layout-%02d-%d-be%v-exec%v-m%d", i, s.Class, s.BigEndian, s.Exec, s.Machine)
		if err := os.WriteFile(filepath.Join(grow, name), []byte(seed), 0o644); err != nil {
			return err
		}
	}
	return nil
}
