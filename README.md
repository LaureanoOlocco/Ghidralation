# Ghidralation — Run IDA Pro Plugins in Ghidra

![Ghidralation Logo](./images/logo.png)

**Ghidralation** is a compatibility layer that allows you to run **IDA Pro plugins inside Ghidra** without modifying their source code.

It works by wrapping IDA SDK function calls and redirecting them to Ghidra's API (e.g., `FlatProgramAPI`, `Memory`, `Listing`, etc.). This enables seamless execution of many FLOSS IDA plugins directly on Ghidra ≥11.3.

---

## 📌 Description

The core idea is to make IDA plugins think they are running inside IDA. Ghidralate does this by emulating the modules `idaapi`, `idc`, `idautils`, `ida_bytes`, etc., using Python scripts that internally call Ghidra's APIs.

- No need to rewrite plugin logic.
- Transparent API translation at runtime.
- Works with GUI and headless Ghidra modes.
- Ideal for security tools, binary analysis, and automated workflows.

---

## ⚙️ Requirements

- **Ghidra 11.3 or higher** (includes PyGhidra by default).
- **Python 3.9+** (ideally via virtual environment).
- **Plugin-specific dependencies**, e.g., `yara-python` for `findcrypt`.

---

## 🚀 How to Use

### GUI Mode

1. **Place the plugin folder inside your Ghidra project**
   - Copy your IDA plugin (e.g., `findcrypt3.py`) to a folder.
   - Add all Ghidralate wrapper files (`main.py`, `cp.py`, `idaapi.py`, etc.) to that same folder.

2. **Launch Ghidra in console mode** (to see output)
   ```bash
   cd $GHIDRA_HOME/support
   ./pyghidraRun --console

## 🧩 Supported Plugins

Currently supported:

- ✅ [Findcrypt](https://github.com/polymorf/findcrypt-yara)

> 🛠️ Support for additional IDA plugins is in progress.  
> Plugins such as **Syms2elf** and **UEFI REtool** are being adapted to work under Ghidralate.


