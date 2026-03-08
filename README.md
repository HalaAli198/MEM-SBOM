# MEM-SBOM: Runtime SBOM Generation from Python Process Memory

Most SBOM tools rely on package metadata or what is installed on the system, which may not reflect what a Python application actually executes.

MEM-SBOM generates **Software Bills of Materials (SBOMs) directly from Python process memory**. By analyzing the garbage collector lists, interpreter state and heap objects, it recovers the modules that were truly loaded at runtime, resolves their versions, and produces a **CycloneDX SBOM**.

This allows investigators to recover an accurate SBOM even when the original system is no longer running, such as after crashes, corruption, or destructive attacks.

---
# Requirements

- Python 3.8 or higher
- Volatility 3 Framework
- `dwarf2json`
- Linux kernel debug symbols (`vmlinux`)
- Python debug symbols matching the Python version used in the memory image

---

# Installation

## 1. Install Volatility 3
MEM-SBOM plugins are built on top of the **Volatility 3 Framework**.

-  Clone the Volatility3 repository and follow the installation instructions at:
https://github.com/volatilityfoundation/volatility3

## 2. Install the dwarf2json Tool
-  Use the `dwarf2json` tool to generate Python symbol tables suitable for Linux and Python internals.
- Clone the dwarf2json repository, place it in the Volaitlity 3 directory, and follow the installation instructions at:
 https://github.com/volatilityfoundation/dwarf2json

 ### 3. Generate Symbol Tables
#### For Linux Kernel:
- Command: ```./dwarf2json linux --elf /path/to/vmlinux > vmlinux-VERSION.json```
- Example: Generate symbol table for Linux (kernel-5.15.0-126): ```./dwarf2json linux --elf vmlinux-5.15.0-126-generic > vmlinux-5.15.0-126-generic.json```
- Place the (.json) file to ``` /path/to/Volatility3/symbols/ directory```.

#### For Python:
 1. Install Python debug build with symbols:
    - Command: ```sudo apt-get install python3.*-dbg ```
    - Example: for Python3.8: ```sudo apt-get install python3.8-dbg```
    - Note: The symbol table depends on the Python version installed on the target system.
 3. Locate the debug build library: ``` find /usr/lib/debug -name "libpython3*.so*"```
 4. Generate the symbol file:
    - Command: ```/dwarf2json linux --elf /path/to/libpython3*.so* > output_filename.json```
    - Example: Generate symbol table for Python3.8: ``` ./dwarf2json linux --elf /usr/lib/debug/usr/lib/libpython3.8d.so.1.0 > python_data_structures.json```
 5. Create the required directory and move the file:
    - Create a folder ('python') in /path/to/volatility3/framework/symbols/generic/types/
    - Place the  (.json) file in the 'python' folder


# Repository Structure

The repository is organized into several directories that contain the MEM-SBOM plugins, supporting components, and example outputs.

## Linux_Plugins

This directory contains the **Volatility 3 plugins for Linux memory analysis**.  
These plugins implement the MEM-SBOM pipeline and supporting functionality.

Main components include:

- **mem_sbom.py**  
  Main orchestrator plugin. Runs the full pipeline and generates the final SBOM output.

- **module_extractor.py**  
  Discovers Python modules from process memory using multiple sources (GC, interpreter registry, and heap).

- **module_classifier.py**  
  Classifies modules as application, third-party, internal, or standard library.

- **dependency_generator.py**  
  Generates dependency relationships between modules by analyzing module dictionary and Python bytecode.

- **bytecode_decoder.py**  
  Handles CPython bytecode decoding across multiple Python versions.

- **py_interpreter.py**  
  Extracts modules registered in the interpreter (`sys.modules`).

- **py_gc.py**  
  Walks Python garbage collector structures to locate tracked Python objects.

- **py_heap.py**  
  Scans process heap memory to identify untracked or hidden Python modules.

- **elf_symbols.py**  
  Helper plugin used to locate the `_PyRuntime` symbol inside ELF binaries during analysis.

---

## Windows_Plugins

This directory contains the **Windows versions of the MEM-SBOM plugins**.

The analysis pipeline is the same as the Linux implementation (module extraction, version resolution, and dependency generation).  
The main difference is the binary parsing layer: Windows plugins use **PE parsing** instead of **ELF parsing** to locate the Python runtime structures (e.g., `_PyRuntime`) within the process memory.


   
