"""Build a standalone executable for the GUI using PyInstaller.

Usage:

    pip install pyinstaller
    python build.py

The resulting binary is placed in the dist/ directory. On Windows the file is
named RSA-OAEP.exe; on Linux and macOS it is just RSA-OAEP. PyInstaller does
not cross-compile, so to produce a Windows executable you must run this script
on a Windows machine with Python and PyInstaller installed.
"""

import os
import shutil
import subprocess
import sys


ROOT = os.path.dirname(os.path.abspath(__file__))
APP_NAME = "RSA-OAEP"
ENTRY_POINT = os.path.join("src", "gui.py")
ASSETS = os.path.join("assets", "logo.png")


def main():
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("[*] PyInstaller is not installed.")
        print("    install it first with:  pip install pyinstaller")
        sys.exit(1)

    # Clean previous build artifacts so the new bundle is reproducible.
    for stale in ("build", "dist", APP_NAME + ".spec"):
        path = os.path.join(ROOT, stale)
        if os.path.isdir(path):
            shutil.rmtree(path)
        elif os.path.isfile(path):
            os.remove(path)

    add_data_arg = ASSETS + os.pathsep + "assets"

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--name", APP_NAME,
        "--onefile",
        "--windowed",
        "--add-data", add_data_arg,
        ENTRY_POINT,
    ]

    print("[*] running PyInstaller")
    print("    " + " ".join(cmd))
    subprocess.check_call(cmd, cwd=ROOT)

    suffix = ".exe" if os.name == "nt" else ""
    output = os.path.join(ROOT, "dist", APP_NAME + suffix)
    if os.path.isfile(output):
        size_kb = os.path.getsize(output) // 1024
        print("[*] build succeeded: " + output + "  (" + str(size_kb) + " KB)")
    else:
        print("[*] build finished but the expected output was not found at " + output)
        sys.exit(1)


if __name__ == "__main__":
    main()
