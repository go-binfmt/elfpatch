// Command bench times elfpatch against NixOS patchelf on real ELF files built
// by gcc, as processes, in interleaved rounds (the tool that goes first
// alternates every round), and prints a Markdown table of medians. Run it
// pinned to one core, from a quiet machine:
//
//	taskset -c 0 ./bench -patchelf $(which patchelf) -elfpatch ./elfpatch
//
// It builds three fixtures: small (a few KiB), 4 MiB and 32 MiB, each linked
// with a long -rpath placeholder so every edit fits in place.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, fixtures); err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(1)
	}
}

type op struct {
	name string
	args []string
	edit bool
}

// run is main without the process: arguments, output and the fixture builder
// are parameters so a test can drive it with stand-in tools.
func run(args []string, w io.Writer, mk func(dir string) ([]fixture, error)) error {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	fs.SetOutput(w)
	pe := fs.String("patchelf", "patchelf", "patchelf binary")
	ep := fs.String("elfpatch", "elfpatch", "elfpatch binary")
	rounds := fs.Int("rounds", 40, "interleaved rounds per operation and file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rounds < 1 {
		return errors.New("-rounds must be at least 1")
	}
	dir, err := os.MkdirTemp("", "elfpatch-bench-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	files, err := mk(dir)
	if err != nil {
		return err
	}
	ver, _ := exec.Command(*pe, "--version").Output()
	fmt.Fprintf(w, "reference: %s; rounds: %d; median wall time per process, interleaved\n\n", strings.TrimSpace(string(ver)), *rounds)

	ops := []op{
		{"--print-rpath", []string{"--print-rpath"}, false},
		{"--print-needed", []string{"--print-needed"}, false},
		{"--set-rpath '$ORIGIN/lib'", []string{"--set-rpath", "$ORIGIN/lib"}, true},
		{"--remove-needed libm.so.6", []string{"--remove-needed", "libm.so.6"}, true},
	}
	fmt.Fprintln(w, "| file | operation | patchelf | elfpatch | speedup |")
	fmt.Fprintln(w, "|---|---|---:|---:|---:|")
	for _, f := range files {
		for _, o := range ops {
			var tp, te []time.Duration
			for r := 0; r < *rounds; r++ {
				order := []*string{pe, ep}
				if r%2 == 1 {
					order = []*string{ep, pe}
				}
				for _, tool := range order {
					d, err := timeOne(dir, *tool, o, f.path)
					if err != nil {
						return fmt.Errorf("%s %s on %s: %w", *tool, o.name, f.name, err)
					}
					if tool == pe {
						tp = append(tp, d)
					} else {
						te = append(te, d)
					}
				}
			}
			mp, me := median(tp), median(te)
			fmt.Fprintf(w, "| %s | `%s` | %s | %s | %.1fx |\n", f.name, o.name, mp.Round(10*time.Microsecond), me.Round(10*time.Microsecond), float64(mp)/float64(me))
		}
	}
	return nil
}

func median(d []time.Duration) time.Duration {
	slices.Sort(d)
	return d[len(d)/2]
}

func timeOne(dir, tool string, o op, src string) (time.Duration, error) {
	target := src
	if o.edit {
		// A fresh copy per run, made outside the timed region.
		target = filepath.Join(dir, "work")
		data, err := os.ReadFile(src)
		if err != nil {
			return 0, err
		}
		if err := os.WriteFile(target, data, 0o755); err != nil {
			return 0, err
		}
	}
	c := exec.Command(tool, append(slices.Clone(o.args), target)...)
	start := time.Now()
	out, err := c.CombinedOutput()
	d := time.Since(start)
	if err != nil {
		return 0, fmt.Errorf("%v: %s", err, out)
	}
	return d, nil
}

type fixture struct{ name, path string }

func fixtures(dir string) ([]fixture, error) {
	var out []fixture
	for _, f := range []struct {
		name string
		mib  int
	}{{"small (~16 KiB)", 0}, {"4 MiB", 4}, {"32 MiB", 32}} {
		src := filepath.Join(dir, "x.c")
		body := "#include <math.h>\nint main(int c, char**v){ return (int)sqrt((double)c) > 9; }\n"
		if f.mib > 0 {
			body = fmt.Sprintf("#include <math.h>\nstatic char big[%d] = {1};\nint main(int c, char**v){ return big[c] + (int)sqrt((double)c) > 9; }\n", f.mib<<20)
		}
		if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
			return nil, err
		}
		bin := filepath.Join(dir, fmt.Sprintf("fixture-%d", f.mib))
		cc := exec.Command("gcc", "-O1", "-o", bin, src, "-lm", "-Wl,--enable-new-dtags", "-Wl,-rpath,/placeholder/"+strings.Repeat("p", 100))
		if b, err := cc.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("gcc: %v: %s", err, b)
		}
		out = append(out, fixture{f.name, bin})
	}
	return out, nil
}
