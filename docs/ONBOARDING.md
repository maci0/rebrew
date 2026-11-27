# Project setup and troubleshooting

Use [Getting started](GETTING_STARTED.md) to onboard a binary and match your
first function. This guide covers setup choices and recovery from common errors.

## Choose a setup command

| Use | When |
| --- | --- |
| `rebrew intake /path/to/game.exe` | Create a project from an existing binary, detect the compiler, discover functions, and scaffold unmatched functions. |
| `rebrew init` | Configure a new project interactively. |
| `rebrew init --no-wizard --target game --binary game.exe --toolchain msvc-6.0` | Scaffold a project with a known target and compiler. Place the binary at `original/game.exe`. |
| `rebrew cfg target add <name> --binary <path>` | Add a target to an existing project. See the [CLI reference](CLI.md#rebrew-cfg-target-add). |

`intake` uses the binary stem as the target name unless you pass `--target`.
For a custom target name, the copied binary uses that name with the original
extension. `intake` needs the target to be configured if the project already
exists. For a target created by intake, repeat the command from the project
root with the copy under `original/`. Intake preserves existing source work
and can remove untouched generated stubs for functions that disappeared.
Copy any reviewed inventory elsewhere first, since intake replaces
`function_structure.json` in `reversed_dir`. For custom binary or inventory
paths, use [manual discovery](#manual-discovery).

### Interactive wizard

With terminal input, `rebrew init` prompts for the binary, compiler profile,
target name, and shell completions that you left unspecified. It looks in
`original/` and the current directory for binaries and uses compiler detection
to suggest a profile. Review the settings at the confirmation prompt. After
creating the scaffold, the wizard can offer to build a missing compiler image.

Use `--no-wizard` or `--json` to skip prompts. Non-interactive input also skips
the wizard. See [init options](CLI.md#rebrew-init).

## Check the project

Run `rebrew doctor` after setup. Use `--json` to collect the report in scripts.
Continue to the [first match walkthrough](GETTING_STARTED.md#4-review-project-status)
when the relevant checks pass.

| Symptom | What to check |
| --- | --- |
| `binary not found` from `intake` | Pass the path to a binary you have. |
| `no functions discovered` | Install `rizin` or configure a compatible `rebrew.discoverers` plugin. The scaffold remains available for another attempt. |
| Missing compiler image | Pull the profile image or build it from the toolchain source checkout. See [compile backends](TOOLCHAIN.md#compile-backends). |
| `Toolchain alignment` fails | Check the binary's compiler and the configured profile. For a project-wide change, use `rebrew cfg set compiler.profile <profile>`. See [per-target compiler overrides](CONFIG.md#per-target-compiler-overrides). |
| Host include or library path is absent | For an image-backed profile, check paths inside the image. A host compiler plugin uses host paths. |
| Binary fails to load | Check the binary path, file integrity, and configured [target format](CONFIG.md#rebrew-projecttoml-project-root). |
| `Cannot extract DLL bytes` during verification | Check the reported address or range against the current binary and its inventory. Repeat discovery or repair the source binding if the binary changed. |
| Project already exists | Use `intake` for discovery on a configured target, or `cfg target add` to add one. |

### 16-bit targets

`intake` sets `arch = "x86_16"` for DOS MZ and Windows NE binaries. Select a
16-bit profile. `verify` compares per-function objects, so Delphi 1.0's
whole-program NE output uses `rebrew build delphi` and
`rebrew binary ne-compare`. See [Delphi whole-program builds](TOOLCHAIN.md#delphi-10-16-bit-ne-whole-program-builds).

## Manual discovery

After a manual `init`, you can generate the function inventory with Rebrew's
discovery backends:

```bash
rebrew binary functions --target game --output src/game/function_structure.json
rebrew doctor --target game
```

For third-party discovery, write a JSON array of objects with integer `va`
and `size` fields and a string `name`. The default inventory is
`function_structure.json` in the target's `reversed_dir`. For a configured
`inventory_file`, write to that path. See [binary functions](CLI.md#rebrew-binary-functions).

## Project instructions and skills

`rebrew init` generates project rules and skills. Use `rebrew init --check`
to report drift and `rebrew init --refresh-agents` to refresh the scaffold.
Keep project-specific rules below the marker in the generated AGENTS.md.
See [init options](CLI.md#rebrew-init).
