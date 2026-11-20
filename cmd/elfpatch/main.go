// Command elfpatch is a pure-Go, patchelf-compatible tool for the subset
// build systems use: --set-rpath, --print-rpath, --set-interpreter,
// --print-interpreter, --remove-needed, --replace-needed, --print-needed,
// --shrink-rpath, --print-soname, --version. Phase 1 edits in place and
// refuses, naming phase 2, anything that would need the file to grow.
package main

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/go-zpkg/elfpatch"
	"github.com/spf13/cobra"
)

// Version may be set with -ldflags "-X main.Version=..."; otherwise the module
// version Go stamped into the binary is used, and "dev" for an unstamped build.
var Version = "dev"

func version() string {
	if Version != "dev" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return Version
}

// osExit is replaceable in tests.
var osExit = os.Exit

const sep = "\x1f"

func main() {
	cmd := RootCmd()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), "elfpatch:", err)
		osExit(1)
	}
}

type opts struct {
	setInterp, setRpath                string
	setInterpSet, setRpathSet          bool
	printInterp, printRpath, printNeed bool
	printSoname                        bool
	force, removeRpath, shrink         bool
	removeNeeded, replaceNeeded        []string
	dryRun                             bool
	output                             string
	version                            bool
	phase2                             map[string]*string
}

// phase2Flags are patchelf operations that need the file to grow; they are
// accepted so the refusal can say why, instead of "unknown flag".
var phase2Flags = []string{"add-needed", "set-soname", "add-rpath", "page-size", "set-os-abi", "add-debug-tag", "no-default-lib", "clear-symbol-version", "rename-dynamic-symbols"}

// RootCmd builds the command.
func RootCmd() *cobra.Command {
	o := &opts{phase2: map[string]*string{}}
	cmd := &cobra.Command{
		Use:   "elfpatch [options] FILE...",
		Short: "patchelf-compatible ELF editor (phase 1: in place only)",
		Long: "elfpatch reads and edits the interpreter, RPATH/RUNPATH and DT_NEEDED of ELF files.\n" +
			"Edits are in place (zero-padded) and verified by re-parsing the output; a value that\n" +
			"does not fit is refused (exit 1, nothing written). Growing .dynstr or PT_INTERP is phase 2.",
		SilenceUsage:       true,
		SilenceErrors:      true,
		DisableFlagParsing: true, // --replace-needed takes two arguments; see mergePairs
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cmd.Flags().Parse(mergePairs(args)); err != nil {
				return err
			}
			if h, _ := cmd.Flags().GetBool("help"); h {
				return cmd.Help()
			}
			return run(cmd, o, cmd.Flags().Args())
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&o.setInterp, "set-interpreter", "", "set PT_INTERP (must fit the existing slot)")
	fl.BoolVar(&o.printInterp, "print-interpreter", false, "print PT_INTERP")
	fl.StringVar(&o.setRpath, "set-rpath", "", "set DT_RUNPATH (DT_RPATH with --force-rpath); must fit the existing slot")
	fl.BoolVar(&o.printRpath, "print-rpath", false, "print DT_RUNPATH, else DT_RPATH")
	fl.BoolVar(&o.force, "force-rpath", false, "with --set-rpath, use DT_RPATH instead of DT_RUNPATH")
	fl.BoolVar(&o.removeRpath, "remove-rpath", false, "delete DT_RPATH/DT_RUNPATH")
	fl.BoolVar(&o.shrink, "shrink-rpath", false, "drop search-path directories that provide no DT_NEEDED library")
	fl.BoolVar(&o.printNeed, "print-needed", false, "print DT_NEEDED, one per line")
	fl.BoolVar(&o.printSoname, "print-soname", false, "print DT_SONAME")
	fl.StringArrayVar(&o.removeNeeded, "remove-needed", nil, "remove DT_NEEDED entries named LIB (repeatable)")
	fl.StringArrayVar(&o.replaceNeeded, "replace-needed", nil, "LIB NEW_LIB: rename DT_NEEDED LIB in place (two arguments; repeatable)")
	fl.BoolVar(&o.dryRun, "dry-run", false, "print the changes, verify them, write nothing")
	fl.StringVar(&o.output, "output", "", "write the result here instead of replacing FILE")
	fl.BoolVar(&o.version, "version", false, "print the version")
	fl.BoolP("help", "h", false, "help")
	for _, n := range phase2Flags {
		o.phase2[n] = fl.String(n, "", "phase 2 (needs growth): not implemented")
		_ = fl.MarkHidden(n)
	}
	return cmd
}

// mergePairs folds "--replace-needed A B" into "--replace-needed=A<sep>B" so
// the flag parser sees one value, as patchelf's two-argument form needs.
func mergePairs(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--replace-needed" && i+2 < len(args) {
			out = append(out, "--replace-needed="+args[i+1]+sep+args[i+2])
			i += 2
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func run(cmd *cobra.Command, o *opts, files []string) error {
	out := cmd.OutOrStdout()
	if o.version {
		fmt.Fprintf(out, "elfpatch %s\n", version())
		return nil
	}
	fl := cmd.Flags()
	o.setInterpSet, o.setRpathSet = fl.Changed("set-interpreter"), fl.Changed("set-rpath")
	for _, n := range phase2Flags {
		if fl.Changed(n) {
			return fmt.Errorf("--%s is not supported yet: it needs the file to grow, which is phase 2 (see README)", n)
		}
	}
	for _, p := range o.replaceNeeded {
		if strings.Count(p, sep) != 1 {
			return errors.New("--replace-needed takes two arguments: LIB NEW_LIB")
		}
	}
	if len(files) == 0 {
		return errors.New("no FILE given (try --help)")
	}
	if o.output != "" && len(files) != 1 {
		return errors.New("--output needs exactly one FILE")
	}
	edits := o.setInterpSet || o.setRpathSet || o.removeRpath || o.shrink || len(o.removeNeeded) > 0 || len(o.replaceNeeded) > 0
	if !edits && !o.printInterp && !o.printRpath && !o.printNeed && !o.printSoname {
		return errors.New("nothing to do (try --help)")
	}
	for _, file := range files {
		if err := one(cmd, o, file, edits); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
	}
	return nil
}

func one(cmd *cobra.Command, o *opts, file string, edits bool) error {
	out := cmd.OutOrStdout()
	if o.printInterp || o.printRpath || o.printNeed || o.printSoname {
		f, err := elfpatch.Open(file)
		if err != nil {
			return err
		}
		defer f.Close()
		if o.printInterp {
			s, ok, err := f.Interpreter()
			if err != nil {
				return err
			}
			if !ok {
				return elfpatch.ErrNoInterp
			}
			fmt.Fprintln(out, s)
		}
		if o.printSoname {
			s, ok, err := f.Soname()
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("no DT_SONAME")
			}
			fmt.Fprintln(out, s)
		}
		if o.printRpath {
			s, _, err := f.SearchPath()
			if err != nil {
				return err
			}
			fmt.Fprintln(out, s)
		}
		if o.printNeed {
			n, err := f.Needed()
			if err != nil {
				return err
			}
			for _, s := range n {
				fmt.Fprintln(out, s)
			}
		}
	}
	if !edits {
		return nil
	}
	po := elfpatch.Options{DryRun: o.dryRun, Output: o.output}
	cs, err := elfpatch.Patch(file, po, func(f *elfpatch.File) ([]elfpatch.Change, error) {
		var all []elfpatch.Change
		add := func(cs []elfpatch.Change, err error) error { all = append(all, cs...); return err }
		if o.setInterpSet {
			if err := add(f.SetInterpreter(o.setInterp)); err != nil {
				return nil, err
			}
		}
		for _, p := range o.replaceNeeded {
			a, b, _ := strings.Cut(p, sep)
			if err := add(f.ReplaceNeeded(a, b)); err != nil {
				return nil, err
			}
		}
		for _, n := range o.removeNeeded {
			if err := add(f.RemoveNeeded(n)); err != nil {
				return nil, err
			}
		}
		if o.setRpathSet {
			if err := add(f.SetRpath(o.setRpath, o.force)); err != nil {
				return nil, err
			}
		}
		if o.removeRpath {
			if err := add(f.RemoveRpath()); err != nil {
				return nil, err
			}
		}
		if o.shrink {
			if err := add(f.ShrinkRpath(elfpatch.OriginDir(file))); err != nil {
				return nil, err
			}
		}
		return all, nil
	})
	if err != nil {
		if errors.Is(err, elfpatch.ErrNoSpace) || errors.Is(err, elfpatch.ErrNoRpath) {
			return fmt.Errorf("%w; nothing written (growing the file is phase 2)", err)
		}
		return err
	}
	if o.dryRun {
		for _, c := range cs {
			fmt.Fprintf(out, "%s: %s\n", file, c)
		}
	}
	return nil
}
