<p align="center"><img src="https://raw.githubusercontent.com/go-binfmt/brand/main/social/go-binfmt-elfpatch.png" alt="go-binfmt/elfpatch" width="720"></p>

# go-binfmt/elfpatch

[![CI](https://github.com/go-binfmt/elfpatch/actions/workflows/ci.yml/badge.svg)](https://github.com/go-binfmt/elfpatch/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-binfmt/elfpatch.svg)](https://pkg.go.dev/github.com/go-binfmt/elfpatch)
[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96)](LICENSE)

A pure-Go replacement for the subset of [NixOS patchelf](https://github.com/NixOS/patchelf)
that package builders use: read and edit the **interpreter**, **RPATH/RUNPATH**,
**DT_SONAME** and **DT_NEEDED** of ELF files, growing the file the way patchelf
does when a value does not fit. No cgo, no C toolchain, static binaries for
Linux, macOS, the BSDs and Windows.

```
go install github.com/go-binfmt/elfpatch/cmd/elfpatch@latest

elfpatch --print-rpath bin/tool
elfpatch --set-rpath '$ORIGIN/../lib' bin/tool
elfpatch --set-interpreter /lib/ld-musl-x86_64.so.1 bin/tool
elfpatch --remove-needed libm.so.6 --shrink-rpath bin/tool
elfpatch --dry-run --set-rpath '$ORIGIN/lib' bin/tool     # prints the change, writes nothing
```

The library is `github.com/go-binfmt/elfpatch` (`Open`, `Parse`, `Patch`, and the
`File` methods `Interpreter`, `Needed`, `Soname`, `Rpath`, `Runpath`,
`SetInterpreter`, `SetRpath`, `AddRpath`, `RemoveRpath`, `RemoveNeeded`,
`ReplaceNeeded`, `AddNeeded`, `SetSoname`, `ShrinkRpath`).

## In place, verified (phase 1)

A value that fits is written **in place**: into the slot the linker reserved,
zero-padded. Phase 2 (below) grows the file when it does not fit; a file that
cannot be grown (no section headers) refuses with `ErrNoSpace`, exit 1, and
nothing is written; a value is never truncated.

| patchelf flag | elfpatch |
|---|---|
| `--print-interpreter`, `--print-rpath`, `--print-needed`, `--print-soname` | same output (`--print-soname` prints nothing, exit 0, when there is none or the file is not a shared object, as patchelf does) |
| `--remove-rpath` | removes the entry (later dynamic entries shift down, as patchelf does) |
| `--shrink-rpath` | drops directories that provide no `DT_NEEDED` library, and duplicates |
| `--remove-needed` | removes the entries; no match is not an error |
| `--version`, `--output FILE`, `--dry-run` | yes (`--dry-run` is ours) |

With several operations on one command line elfpatch applies them in patchelf's
order: soname, interpreter, one rpath operation (shrink, else remove, else set,
else add), remove-needed, replace-needed, add-needed.

Every in-place write goes through the same checks:

* **Parse by program headers** (`PT_INTERP`, `PT_DYNAMIC`, `PT_LOAD`), 32/64-bit,
  both byte orders; works on stripped files with no section headers. Every
  offset and size is checked against the file length without overflowing
  `uint64`, and the whole file is capped at 2 GiB so it is safe on 32-bit.
* **Shared strings are never overwritten.** Linkers merge string tails in
  `.dynstr`. Zero-padding a slot that another name points into (a `DT_NEEDED`, a
  `.dynsym` name, a version need/definition) would corrupt that name, so such
  an edit does not go in place: it grows (phase 2), or, on a file that cannot
  grow, is refused (`ErrAmbiguous`).
* **Atomic.** A temp file in the same directory is created from the original,
  only the edited byte ranges are written into it, the mode (including setuid)
  is applied, then it is renamed over the target. A symlink is followed, so the
  link survives. `--output` writes elsewhere instead.
* **Verified after the write.** The temp file is *re-parsed* before the rename
  and compared with the input: same length, byte-identical everywhere outside
  the ranges the edit declared, the declared ranges hold exactly the intended
  bytes, and every field the edit did not target (interpreter, needed, soname,
  rpath/runpath, class, machine) reads back unchanged. Otherwise `ErrVerify`
  and nothing is renamed.
* **Fuzzed.** `FuzzParse` feeds arbitrary bytes to the parser and to every edit
  plus the verifier; the corpus is committed under `testdata/fuzz/FuzzParse`.
  CI replays it and fuzzes 60 s per run.

## Phase 2: growth, the way patchelf does it

A value that does not fit is no longer refused: the file grows. The layout
engine (`layout.go`) is a port of the section-replacement half of **patchelf
0.19.3** (`src/patchelf.cc`: `replaceSection`, `writeReplacedSections`,
`rewriteSectionsLibrary`, `rewriteSectionsExecutable`, `shiftFile`,
`trimLoadSegments`, `normalizeNoteSegments`, `rewriteHeaders`):

* the new string is appended to `.dynstr` (or `.interp` is rewritten, or an
  entry is added at the top of `.dynamic`), and the section that grew is
  **replaced** by a larger copy, placed in new space;
* a **shared library** gets that space at the end of the file, in a new
  `PT_LOAD` after the last page, or by extending the last `PT_LOAD` when it is
  read-write and ends where the file does; the program headers stay at the
  front when they fit and move there when they do not;
* an **executable** cannot move its code, so the sections in front of it
  (`.interp`, notes, hash tables, `.dynsym`, `.dynstr`) are moved into the
  header page, the file after them is shifted by whole pages, and the header
  `PT_LOAD` is reused, or split into its own read-write one;
* the **page size** comes from `e_machine` (`patchelf.cc` 382-406: 64 KiB for
  aarch64, ppc, mips, ia64, alpha, tilegx, loongarch; 8 KiB for sparc; 4 KiB
  otherwise), or from `--page-size`;
* then the program and section headers are rewritten and sorted, the addresses
  in `.dynamic` follow their sections, and `st_shndx` follows the new section
  order in `.dynsym` and `.symtab`.

ELF32 and ELF64, both byte orders; every value written into an ELF32 field is
checked against 32 bits, and a result over 2 GiB is refused. Growth needs
section headers (patchelf refuses a file without them too): a stripped-of-
sections file that needs room gets the same `ErrNoSpace` refusal as in phase 1,
now carrying the reason.

| patchelf flag | elfpatch phase 2 |
|---|---|
| `--set-interpreter` | in place when it fits (patchelf always relocates), else `.interp` moves |
| `--set-rpath` (`--force-rpath`) | in place when it fits and nothing else shares the string; **else appended to `.dynstr`**; no entry yet: a `DT_RUNPATH` (`DT_RPATH`) is added |
| `--add-rpath DIRS` | `old:DIRS` set as above; adds a `DT_RUNPATH` when there is none |
| `--set-soname` | shared objects only (patchelf ignores it on `ET_EXEC`): in place when it fits, else appended; none yet: `DT_SONAME` added |
| `--add-needed LIB` | repeatable; names sorted and added at the **top** of `.dynamic`, so they are searched first (a name already needed is added again, as patchelf does) |
| `--replace-needed OLD NEW` | in place when it fits and is unshared; else appended (a suffix of the old name just points into it), and the **version-needed** file names follow |
| `--page-size N` | page size for the layout |

Not done: `--set-os-abi`, `--add-debug-tag`, `--no-default-lib`,
`--clear-symbol-version`, `--rename-dynamic-symbols`, `--build-resolution-cache`,
a file with a `.note.nixos.ldcache` note, a file with both `DT_RPATH` and
`DT_RUNPATH` under `--set-rpath`, and `.gnu.version_r` names that live outside
`.dynstr`. Each is refused with nothing written.

### What "verified" means for a grown file

The byte-range check of phase 1 cannot judge a file whose layout changed, so
`verifyGrown` judges it by structure, on the temp file as it was written and
before the rename:

* the written bytes are the editor's image and it re-parses; the ELF header is
  unchanged but for the table offsets and counts;
* every section is still there with the same type, flags, links and contents;
  only `.interp`, `.dynstr` and `.dynamic` may change size, and `.dynstr` only
  by appending; a section whose address changed must be one patchelf may move
  (anything but `PROGBITS`, and `.interp`); `.dynamic` differs only in the
  entries the edit named and in addresses that follow their section; symbols
  differ only in `st_shndx` following the sections;
* every symbol and version name still reads the same string (a renamed
  `DT_NEEDED` is the one allowed difference), and every field the edit did not
  target reads back unchanged;
* the program headers describe the new file: each allocated section sits in a
  `PT_LOAD` at the offset its address implies, with the permissions its flags
  need; `PT_INTERP`, `PT_DYNAMIC`, `PT_PHDR` match their section or table; the
  other segments keep their addresses and sizes; `PT_LOAD`s do not overlap and
  are congruent with their offsets; none became writable and executable.

Anything else is `ErrVerify` and nothing is renamed.

## Tested against patchelf

`differential_test.go` (edits in place) and `differential_growth_test.go`
(growth) build real ELF files with gcc (executables, PIE and not, linked with
`-Wl,-rpath` placeholders or none, and shared libraries), apply the same edit
with patchelf and with elfpatch, and compare:

* what `readelf -d -l -V` reports for `NEEDED`, `SONAME`, `RPATH`, `RUNPATH`,
  the program interpreter, the version-needed file names and the kinds of
  program header, line by line;
* every `--print-*` output, byte for byte, success and failure alike;
* that `readelf -a` has no warning or error about the result;
* that an edit in place did **not grow** the file;
* that the patched program still **runs** with no `LD_LIBRARY_PATH` (for a
  library: a program linked against the edited library, run), which is the only
  test that the loader accepts the new layout.

The growth cases: a long interpreter (a copy of the real loader under a long
path), a long rpath and one over 8 KiB, `--force-rpath`, an rpath where there is
none (`--set-rpath`, `--add-rpath`), `--add-needed` once and twice,
`--replace-needed` with a longer name and of `libm` (version needs),
`--set-soname` on a library with and without one, `--page-size`, and
combinations, on PIE and non-PIE executables and libraries.

It runs in CI on Ubuntu against the patchelf from apt (the version the job
prints; 0.18.0 on the current runner image), and is *required* there. A second
job, `layout-oracle`, runs the growth cases against **patchelf 0.19.3 built from
its tag** with `ELFPATCH_LAYOUT_STRICT=1`: the same `PT_LOAD` flags, the same
file size and the same `readelf -l -S` tables as the release the engine was
ported from. (Locally the lane also passed on linux/arm64, 64 KiB pages, and on
linux/amd64 under emulation.) On a machine without Linux, gcc, readelf or
patchelf it skips with the reason stated. Nothing binary is committed: the
fixtures are built from small C files at test time. Synthetic images
(`internal/elfgen`, all four class/endianness combinations, executables and
libraries with section headers, three page sizes, notes, version needs, merged
string tails) cover what gcc cannot build here.

`FuzzGrow` feeds arbitrary bytes to the layout engine, every growth edit (with
and without a forced page size, including one past the 2 GiB cap) and the
verifier; its corpus is under `testdata/fuzz/FuzzGrow` and CI fuzzes it for 60
seconds per run, next to `FuzzParse`.

## Benchmark

Single core, process wall time, interleaved rounds, medians, against patchelf
on the same files (`internal/bench`, run pinned with `taskset -c 0`). Fixtures
are gcc-built executables with a long `-rpath` placeholder so every edit fits.

Ubuntu x86-64 GitHub runner (the CI `bench` job, run 44719076189, pinned to one core
with taskset, load average 0.7), patchelf 0.18.0 from apt, 60 interleaved rounds, median
wall time of the whole process:

| file | operation | patchelf | elfpatch | patchelf / elfpatch |
|---|---|---:|---:|---:|
| small (~16 KiB) | `--print-rpath` | 1.18ms | 1.94ms | 0.6x |
| small (~16 KiB) | `--print-needed` | 1.16ms | 1.94ms | 0.6x |
| small (~16 KiB) | `--set-rpath '$ORIGIN/lib'` | 1.34ms | 2.17ms | 0.6x |
| small (~16 KiB) | `--remove-needed libm.so.6` | 1.33ms | 2.21ms | 0.6x |
| 4 MiB | `--print-rpath` | 2.91ms | 2.01ms | 1.4x |
| 4 MiB | `--print-needed` | 2.96ms | 2.04ms | 1.4x |
| 4 MiB | `--set-rpath '$ORIGIN/lib'` | 10.55ms | 9.63ms | 1.1x |
| 4 MiB | `--remove-needed libm.so.6` | 10.57ms | 9.66ms | 1.1x |
| 32 MiB | `--print-rpath` | 18.35ms | 2.22ms | 8.3x |
| 32 MiB | `--print-needed` | 18.39ms | 2.23ms | 8.3x |
| 32 MiB | `--set-rpath '$ORIGIN/lib'` | 122.35ms | 102.19ms | 1.2x |
| 32 MiB | `--remove-needed libm.so.6` | 122.35ms | 106.97ms | 1.1x |

On a developer machine (linux/arm64 container on Apple silicon, 30 rounds) the large-file
edits are about even with patchelf (0.8-0.9x) and prints are 1.4-1.5x faster; the small-file
gap is the same.

Reading it: a Go process starts slower than a C one, and the cobra command tree
the fleet standardises on adds to that, so on a 16 KiB file elfpatch is behind
by that fixed start-up cost. The work itself scales better: elfpatch maps the
file and reads only the pages it needs, where patchelf reads the whole file, so
prints on large binaries are faster. Edits create the new file with
`copy_file_range` and verify it, which keeps them close to patchelf on large
files. Tracked as an open performance issue; see the repository's issues.

## Development

```
go test ./...                                  # unit, CLI, fuzz-corpus replay; differential skips without Linux tools
go run ./internal/mkcorpus                     # regenerate testdata/ (fixtures and fuzz seeds)
go test -fuzz FuzzParse -fuzztime 60s .
go run ./internal/bench -patchelf $(which patchelf) -elfpatch ./elfpatch
```

Licence: BSD-3-Clause.
