# ZydisExample

This is a small project that shows how to use **Zydis**.
It loads a PE file from disk, scans for byte patterns, and then disassembles instructions around the matches.

## What it does

- Reads a PE file (like a `.sys` or `.exe`) from disk
- Finds bytes with a simple pattern scan
- Uses Zydis to decode + format x64 instructions

## Install Zydis with vcpkg

This project is set up to use vcpkg through MSBuild. It will look for vcpkg in:
- `VCPKG_ROOT` (environment variable), or
- `C:\vcpkg` (fallback)

1) Install vcpkg (once):

```powershell
git clone https://github.com/microsoft/vcpkg
cd vcpkg
.\bootstrap-vcpkg.bat
```

2) Install Zydis (x64, static, MSVC runtime MD):

```powershell
.\vcpkg install zydis:x64-windows-static-md
```

3) Integrate vcpkg with Visual Studio (recommended):

```powershell
.\vcpkg integrate install
```

If you don’t want global integration, you can also pass the toolchain file to CMake builds. (This repo is a Visual Studio solution though.)

## Build (Visual Studio 2022)

- Open `ZydisExample.sln`
- Select **Release** + **x64**
- Build

## Run

By default the sample tries to load a specific file path. If it can’t find your file, just change the path in `ZydisExample/main.cpp` and run again.

Credits to [@dword64](https://github.com/dword64) 
