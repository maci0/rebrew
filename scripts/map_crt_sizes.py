import os
import subprocess
from pathlib import Path


def main():
    src_dir = Path("tools/MSVC600/VC98/CRT/SRC")
    c_files = list(src_dir.glob("*.C"))

    print(f"Compiling {len(c_files)} CRT source files...")

    compile_cmd = [
        "wine",
        "tools/MSVC600/VC98/BIN/CL.EXE",
        "/nologo",
        "/c",
        "/MT",
        "/Gd",
        "/O1",
        "/Itools/MSVC600/VC98/INCLUDE",
        "/Itools/MSVC600/VC98/CRT/SRC",
        "-DWIN32",
        "-D_WIN32",
        "-DWINHEAP",
    ]

    obj_dir = Path("crt_objs")
    obj_dir.mkdir(exist_ok=True)

    env = os.environ.copy()

    for c_file in c_files:
        obj_file = obj_dir / (c_file.stem + ".obj")
        cmd = compile_cmd + [f"/Fo{obj_file}", str(c_file)]
        res = subprocess.run(cmd, capture_output=True, text=True, env=env)

    print("Analyzing .obj files with nm for function sizes...")
    for obj_file in obj_dir.glob("*.obj"):
        try:
            res = subprocess.run(
                ["x86_64-w64-mingw32-nm", "--print-size", "--radix=d", str(obj_file)],
                capture_output=True,
                text=True,
            )
            if res.returncode == 0:
                stdout = res.stdout
                lines = [
                    linex
                    for linex in stdout.splitlines()
                    if (" T " in linex or " t " in linex) and len(linex.split()) >= 4
                ]
                if lines:
                    print(f"\n--- {obj_file.name} ---")
                    for line in lines:
                        parts = line.split()
                        _, size, _, name = parts[0], parts[1], parts[2], parts[3]
                        print(f"{name.strip('_')[:30]:<30} {size:>4}B")
        except Exception:
            pass


if __name__ == "__main__":
    main()
