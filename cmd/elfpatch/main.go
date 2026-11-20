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

	"github.com/go-binfmt/elfpatch"
	"github.com/spf13/cobra"
)

// Version may be set with -ldflags "-X main.Version=..."; otherwise the module
// version Go stamped into the binary is used, and "dev" for an unstamped build.
var Version = "dev"

// readBuildInfo is replaceable in tests.
var readBuildInfo = debug.ReadBuildInfo

func version() string {
	if Version != "dev" {
		return Version
	}
	if bi, ok := readBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
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
	addNeeded                          []string
	setSoname, addRpath                string
	setSonameSet, addRpathSet          bool
	pageSize                           uint64
	dryRun                             bool
	output                             string
	version                            bool
	unsupported                        map[string]*string
}

// unsupportedFlags are patchelf operations elfpatch does not implement; they
// are accepted so the refusal can say so, instead of "unknown flag".
var unsupportedFlags = []string{"set-os-abi", "add-debug-tag", "no-default-lib", "clear-symbol-version", "rename-dynamic-symbols", "build-resolution-cache"}

// RootCmd builds the command.
func RootCmd() *cobra.Command {
	o := &opts{unsupported: map[string]*string{}}
	cmd := &cobra.Command{
		Use:   "elfpatch [options] FILE...",
		Short: "patchelf-compatible ELF editor",
		Long: "elfpatch reads and edits the interpreter, RPATH/RUNPATH, DT_SONAME and DT_NEEDED of ELF files.\n" +
			"A value that fits is written in place; one that does not grows the file the way patchelf\n" +
			"does (a new or extended PT_LOAD). Every result is re-parsed and verified before it is renamed\n" +
			"over the input; a file that cannot be grown or verified is refused (exit 1, nothing written).",
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
	fl.StringVar(&o.setInterp, "set-interpreter", "", "set PT_INTERP (in place when it fits, else the file grows)")
	fl.BoolVar(&o.printInterp, "print-interpreter", false, "print PT_INTERP")
	fl.StringVar(&o.setRpath, "set-rpath", "", "set DT_RUNPATH (DT_RPATH with --force-rpath); adds the entry when there is none")
	fl.StringVar(&o.addRpath, "add-rpath", "", "append DIRS to the search path (adds a DT_RUNPATH when there is none)")
	fl.StringVar(&o.setSoname, "set-soname", "", "set DT_SONAME of a shared library")
	fl.StringArrayVar(&o.addNeeded, "add-needed", nil, "add a DT_NEEDED entry for LIB at the top of .dynamic (repeatable)")
	fl.Uint64Var(&o.pageSize, "page-size", 0, "page size to use when the file grows (default: by machine, as patchelf)")
	fl.BoolVar(&o.printRpath, "print-rpath", false, "print DT_RUNPATH, else DT_RPATH")
	fl.BoolVar(&o.force, "force-rpath", false, "with --set-rpath, use DT_RPATH instead of DT_RUNPATH")
	fl.BoolVar(&o.removeRpath, "remove-rpath", false, "delete DT_RPATH/DT_RUNPATH")
	fl.BoolVar(&o.shrink, "shrink-rpath", false, "drop search-path directories that provide no DT_NEEDED library")
	fl.BoolVar(&o.printNeed, "print-needed", false, "print DT_NEEDED, one per line")
	fl.BoolVar(&o.printSoname, "print-soname", false, "print DT_SONAME")
	fl.StringArrayVar(&o.removeNeeded, "remove-needed", nil, "remove DT_NEEDED entries named LIB (repeatable)")
	fl.StringArrayVar(&o.replaceNeeded, "replace-needed", nil, "LIB NEW_LIB: rename DT_NEEDED LIB (two arguments; repeatable)")
	fl.BoolVar(&o.dryRun, "dry-run", false, "print the changes, verify them, write nothing")
	fl.StringVar(&o.output, "output", "", "write the result here instead of replacing FILE")
	fl.BoolVar(&o.version, "version", false, "print the version")
	fl.BoolP("help", "h", false, "help")
	for _, n := range unsupportedFlags {
		o.unsupported[n] = fl.String(n, "", "not implemented")
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
	o.setSonameSet, o.addRpathSet = fl.Changed("set-soname"), fl.Changed("add-rpath")
	for _, n := range unsupportedFlags {
		if fl.Changed(n) {
			return fmt.Errorf("--%s is not supported by elfpatch (see README)", n)
		}
	}
	if o.setRpathSet && o.addRpathSet {
		return errors.New("--set-rpath option not allowed with --add-rpath") // patchelf's own message
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
	edits := o.setInterpSet || o.setRpathSet || o.addRpathSet || o.setSonameSet || o.removeRpath || o.shrink ||
		len(o.removeNeeded) > 0 || len(o.replaceNeeded) > 0 || len(o.addNeeded) > 0
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
		if o.printSoname && f.Type == 3 { // patchelf: only shared objects (ET_DYN) have a soname to print
			s, ok, err := f.Soname()
			if err != nil {
				return err
			}
			if ok && s != "" { // patchelf prints nothing when there is none, and exits 0
				fmt.Fprintln(out, s)
			}
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
	if edits {
		return edit(cmd, o, file)
	}
	return nil
}

func edit(cmd *cobra.Command, o *opts, file string) error {
	out := cmd.OutOrStdout()
	po := elfpatch.Options{DryRun: o.dryRun, Output: o.output, PageSize: o.pageSize}
	cs, err := elfpatch.Patch(file, po, func(f *elfpatch.File) ([]elfpatch.Change, error) {
		var all []elfpatch.Change
		add := func(cs []elfpatch.Change, err error) error { all = append(all, cs...); return err }
		// patchelf's order (patchElf2): soname, interpreter, one rpath
		// operation (shrink, else remove, else set, else add), then the
		// needed entries removed, replaced, added.
		if o.setSonameSet {
			if err := add(f.SetSoname(o.setSoname)); err != nil {
				return nil, err
			}
		}
		if o.setInterpSet {
			if err := add(f.SetInterpreter(o.setInterp)); err != nil {
				return nil, err
			}
		}
		var err error
		switch {
		case o.shrink:
			err = add(f.ShrinkRpath(elfpatch.OriginDir(file)))
		case o.removeRpath:
			err = add(f.RemoveRpath())
		case o.setRpathSet:
			err = add(f.SetRpath(o.setRpath, o.force))
		case o.addRpathSet:
			err = add(f.AddRpath(o.addRpath, o.force))
		}
		if err != nil {
			return nil, err
		}
		for _, n := range o.removeNeeded {
			if err := add(f.RemoveNeeded(n)); err != nil {
				return nil, err
			}
		}
		for _, p := range o.replaceNeeded {
			a, b, _ := strings.Cut(p, sep)
			if err := add(f.ReplaceNeeded(a, b)); err != nil {
				return nil, err
			}
		}
		if len(o.addNeeded) > 0 {
			if err := add(f.AddNeeded(o.addNeeded...)); err != nil {
				return nil, err
			}
		}
		return all, nil
	})
	if err != nil {
		return err
	}
	if o.dryRun {
		for _, c := range cs {
			fmt.Fprintf(out, "%s: %s\n", file, c)
		}
	}
	return nil
}
