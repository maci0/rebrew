# recompile.online

Compiler-as-a-service API over the rebrew toolchain zoo. Submit C source
with a toolchain id and get back the compiled artifact — each compile runs
inside the matching pinned toolchain container (`rebrew/msvc:6.0-win32`
etc.), so the environment is sandboxed and reproducible.

## API

```
GET  /api/v1/compilers        → [{id, family, version, target, runtime, flags_style, obj_ext, description}]
POST /api/v1/compile          → CompileResult {id, compiler, status, artifact_url, compiler_version, warnings, log}
GET  /api/v1/artifacts/{id}   → the compiled artifact bytes
```

`POST /api/v1/compile` body:

```json
{
  "compiler": "msvc6",
  "source": "int add(int a, int b) { return a + b; }\n",
  "flags": ["/O1", "/Gd"]
}
```

## Run

```bash
uv sync                    # installs rebrew (path dep) + fastapi/uvicorn
uv run uvicorn recompile.app:app --port 8000
# or: uv run recompile-api
```

The service shells out to the docker CLI (mount the docker socket when
containerized) and requires the toolchain images to be built:

```bash
rebrew toolchain build msvc6
rebrew toolchain build msvc1.52
rebrew toolchain build delphi16
rebrew toolchain build watcom
```

## Layout

```
recompile/
├── pyproject.toml      # service package (rebrew as a path dependency)
└── recompile/
    ├── app.py          # FastAPI routes
    ├── models.py       # request/response schemas
    ├── compilers.py    # toolchain catalog (from rebrew.toolchain)
    └── executor.py     # docker-run compile dispatch + artifact store
```

Compiled artifacts land in `recompile/artifacts/` (gitignored).
