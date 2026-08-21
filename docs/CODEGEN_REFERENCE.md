# Compiler Codegen Reference

Superseded — this document has been replaced by the per-compiler-version
reference in **[codegen/](codegen/README.md)**: one file per compiler
major version with minute byte-level codegen patterns, how adjacent major
versions differ, and verified "100% unique" markers.

The fingerprint catalog, the shared per-file template, the uniqueness
table and the verification methodology now live in
[codegen/README.md](codegen/README.md).  Add new fingerprints to the
per-version file of the compiler that produces them, then to the
uniqueness table, before wiring a detector into `toolchain_detect.py`.
