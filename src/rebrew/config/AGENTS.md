# AGENTS.md: config/

Centralized project configuration loader (`rebrew-project.toml`), environment variable validators, address-comment dialect settings, and `ProjectConfig`.

## Modules

| Module | Role |
|--------|------|
| `__init__.py` | Public configuration API re-exports and `__all__` |
| `constants.py` | Constants, `ConfigWarning`, `ARCH_PRESETS`, `LinkConfig`, and known key sets |
| `env.py` | `REBREW_*` env knob validators, URL safety checks, and LLM budgets |
| `schema.py` | `msgspec.Struct` section schemas, field parsers, and TOML table checks |
| `address_comments.py` | `AddressCommentFormat` dialects and cached per-file comment layouts |
| `project.py` | `ProjectConfig` dataclass, binary layout detection, and `load_config` |

Externals (the only packages this one may import): `buildsys.layout_meta`, `compiler.cache`, `compiler.toolchain`, `compiler.toolchain_paths`, `compiler.toolchain_spec`, `errors`, `formats.binary_loader`, `formats.pe_headers`, `metadata.storage`, `registry`, `utils`, `workspace`. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- Public configuration symbols remain re-exported at `rebrew.config`.
- Every boolean key parsed in loader logic stays covered by `_BOOL_CONFIG_KEYS`.
