# elfpatch

A pure-Go replacement for the subset of [NixOS patchelf](https://github.com/NixOS/patchelf)
that package builders use: read and edit the **interpreter**, **RPATH/RUNPATH**
and **DT_NEEDED** of ELF files. No cgo, no C toolchain, static binaries for
Linux, macOS, the BSDs and Windows.

```
go install github.com/go-zpkg/elfpatch/cmd/elfpatch@latest

elfpatch --print-rpath bin/tool
elfpatch --set-rpath '$ORIGIN/../lib' bin/tool
elfpatch --set-interpreter /lib/ld-musl-x86_64.so.1 bin/tool
elfpatch --remove-needed libm.so.6 --shrink-rpath bin/tool
elfpatch --dry-run --set-rpath '$ORIGIN/lib' bin/tool     # prints the change, writes nothing
```

The library is `github.com/go-zpkg/elfpatch` (`Open`, `Parse`, `Patch`, and the
`File` methods `Interpreter`, `Needed`, `Soname`, `Rpath`, `Runpath`,
`SetInterpreter`, `SetRpath`, `RemoveRpath`, `RemoveNeeded`, `ReplaceNeeded`,
`ShrinkRpath`).

## Phase 1: in place, verified

Phase 1 edits **in place**: a new value is written into the slot the linker
reserved and zero-padded. A value that does not fit is **refused**
(`ErrNoSpace`, exit 1, naming phase 2) and nothing is written; it is never
truncated.

| patchelf flag | elfpatch phase 1 |
|---|---|
| `--print-interpreter`, `--print-rpath`, `--print-needed`, `--print-soname` | same output |
| `--set-interpreter` | in place, must fit `p_filesz` |
| `--set-rpath` (`--force-rpath`) | in place, must fit the existing string; converts `DT_RPATH` to `DT_RUNPATH` like patchelf; no entry yet is `ErrNoRpath` |
| `--remove-rpath` | removes the entry (later dynamic entries shift down, as patchelf does) |
| `--shrink-rpath` | drops directories that provide no `DT_NEEDED` library, and duplicates |
| `--remove-needed` | removes the entries; no match is not an error |
| `--replace-needed OLD NEW` | in place, `NEW` must fit `OLD`'s string |
| `--add-needed`, `--set-soname`, `--add-rpath`, `--page-size`, ... | **phase 2**: refused naming it |
| `--version`, `--output FILE`, `--dry-run` | yes (`--dry-run` is ours) |

Every write goes through the same checks:

* **Parse by program headers** (`PT_INTERP`, `PT_DYNAMIC`, `PT_LOAD`), 32/64-bit,
  both byte orders; works on stripped files with no section headers. Every
  offset and size is checked against the file length without overflowing
  `uint64`, and the whole file is capped at 2 GiB so it is safe on 32-bit.
* **Shared strings are refused.** Linkers merge string tails in `.dynstr`.
  Zero-padding a slot that another name points into (a `DT_NEEDED`, a
  `.dynsym` name, a version need/definition) would corrupt that name, so the
  edit is refused (`ErrAmbiguous`) instead.
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

### Phase 2 (not done)

Growing a string that does not fit: patchelf adds a `PT_LOAD` and moves
`.dynstr` / `PT_INTERP` there (its page size comes from `e_machine`,
`patchelf.cc` 382-406), then fixes `.dynamic`, `.dynsym` references, section
headers and the hash tables. Phase 2 does the same, plus `--add-needed`,
`--set-soname`, `--add-rpath` and adding an rpath where there is none.

## Tested against patchelf

`differential_test.go` builds real ELF files with gcc (a shared library plus
three executables linked with `-Wl,-rpath` placeholders: `DT_RUNPATH`,
`DT_RPATH`, and a mixed path with real and missing directories), applies the
same edit with patchelf and with elfpatch, and compares:

* what `readelf -d -l` reports for `NEEDED`, `SONAME`, `RPATH`, `RUNPATH` and
  the program interpreter, line by line;
* every `--print-*` output, byte for byte, success and failure alike;
* that the file did **not grow** (patchelf may move things, we must not);
* that the patched program still **runs** (an edit that sets the rpath must find
  its library with no `LD_LIBRARY_PATH`).

It runs in CI on Ubuntu (patchelf from apt) and is *required* there; on a
machine without Linux, gcc, readelf or patchelf it skips with the reason stated.
Nothing binary is committed: the fixtures are built from two tiny C files at
test time. Synthetic images (`internal/elfgen`, all four class/endianness
combinations) cover what gcc cannot build here, including merged string tails.

## Benchmark

Single core, process wall time, interleaved rounds, medians, against patchelf
on the same files (`internal/bench`, run pinned with `taskset -c 0`). Fixtures
are gcc-built executables with a long `-rpath` placeholder so every edit fits.

patchelf 0.18.0 (Debian trixie), linux/arm64 in a container on Apple silicon,
30 rounds. The CI `bench` job prints the same table on the Ubuntu x86-64 runner.

| file | operation | patchelf | elfpatch | patchelf / elfpatch |
|---|---|---:|---:|---:|
| small (~16 KiB) | `--print-rpath` | 610µs | 1.71ms | 0.4x |
| small (~16 KiB) | `--print-needed` | 580µs | 1.68ms | 0.3x |
| small (~16 KiB) | `--set-rpath '$ORIGIN/lib'` | 620µs | 1.74ms | 0.4x |
| small (~16 KiB) | `--remove-needed libm.so.6` | 620µs | 1.75ms | 0.4x |
| 4 MiB | `--print-rpath` | 1.29ms | 1.85ms | 0.7x |
| 4 MiB | `--print-needed` | 1.3ms | 1.84ms | 0.7x |
| 4 MiB | `--set-rpath '$ORIGIN/lib'` | 1.97ms | 3.03ms | 0.6x |
| 4 MiB | `--remove-needed libm.so.6` | 1.95ms | 3.21ms | 0.6x |
| 32 MiB | `--print-rpath` | 3.15ms | 2.23ms | 1.4x |
| 32 MiB | `--print-needed` | 3.06ms | 2.07ms | 1.5x |
| 32 MiB | `--set-rpath '$ORIGIN/lib'` | 7.79ms | 9.21ms | 0.8x |
| 32 MiB | `--remove-needed libm.so.6` | 7.97ms | 9.17ms | 0.9x |

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
