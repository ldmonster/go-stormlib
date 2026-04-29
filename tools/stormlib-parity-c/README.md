# tools/stormlib-parity-c

`stormlib-parity-c`: native C++ binary that implements the parity command
contract (see [../parity/README.md](../parity/README.md)) using the
upstream StormLib library. It is the reference implementation that
`go-stormlib` is compared against.

## Source

A single translation unit, [main.cpp](main.cpp), linked against StormLib.
The contract version (`kVersion`) must be kept in lockstep with
[../paritycmd/root.go](../paritycmd/root.go) (`ParityCmdVersion`).

## Build

The expected target name is `stormlib-parity-c`. The repo Taskfile wraps
the typical CMake invocation:

```bash
task cparity:build
```

This either builds against an in-tree `CMakeLists.txt`, or builds the
StormLib submodule with `STORM_BUILD_PARITYCMD=ON`. If neither path
produces the binary, the Task copies `bin/stormlib-parity` to
`build/stormlib-parity-c` so the C-backed parity workflow can still run
end-to-end (with the obvious caveat that "C-backed" then means "Go-backed
fallback" — drift checks therefore report 0 deltas).

Manual build (out-of-tree, against a system StormLib):

```bash
mkdir -p build && cd build
cmake -S ../tools/stormlib-parity-c -B . -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

## Usage

The CLI surface mirrors [tools/paritycmd](../paritycmd/README.md). See that
README for flag and exit-code semantics.

## Wiring it into the parity suites

```bash
export STORMLIB_PARITY_C_CMD=$PWD/build/stormlib-parity-c
task parity:c-backed
task parity:c-backed-drift-check
```
