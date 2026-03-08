# MEM-SBOM: Runtime SBOM Generation from Python Process Memory

Most SBOM tools rely on package metadata or what is installed on the system, which may not reflect what a Python application actually executes.

MEM-SBOM generates **Software Bills of Materials (SBOMs) directly from Python process memory**. By analyzing the garbage collector lists, interpreter state and heap objects, it recovers the modules that were truly loaded at runtime, resolves their versions, and produces a **CycloneDX SBOM**.

This allows investigators to recover an accurate SBOM even when the original system is no longer running, such as after crashes, corruption, or destructive attacks.

---


## Key Capabilities
- **Three-source module discovery**
   Combines interpreter state (sys.modules), GC linked-list walking, and brute-force heap scanning to find every loaded Python module — including hidden, unlinked, and GC-untracked objects.

 - **Cross-process extraction**
    Automatically discovers child processes (workers, forks) and merges module lists across the entire application tree.

  - **Version extraction from live objects** 
    Reads __version__, VERSION, version_info and other attributes directly from module dicts in memory, with fallback to installed package metadata

- **Memory-based SBOM generation**  
  Generates Software Bills of Materials directly from Python process memory rather than relying on package metadata.

- **Dependency graph generation**
   Analyzes function bytecode (IMPORT_NAME, IMPORT_FROM, CALL targets), module dicts, class hierarchies, and func_module pointers to build a complete dependency graph.

- **CycloneDX SBOM output**  
  Produces standards-compliant SBOMs (components, dependency relationships, and memory-extraction provenance) that can be integrated with existing vulnerability and supply-chain analysis tools.
- **Python 3.6–3.14 support**
  Version-aware bytecode decoder, GC layout handling (generational → incremental), and interpreter state resolution across all modern CPython versions.

- **Cross-platform analysis pipeline**  
   Supports both Linux and Windows Operating Systems.



 --- 
# Requirements

- Python 3.8 or higher
- Volatility 3 Framework
- `dwarf2json`
- Linux kernel debug symbols (`vmlinux`)
- Python debug symbols matching the Python version used in the memory image

---

# Installation
## 1.Clone this repository
  git clone https://github.com/HalaAli198/MEM-SBOM.git

## 12. Install Volatility 3
  Since MEM-SBOM plugins are built on top of the **Volatility 3 Framework**: Clone the Volatility3 repository and follow the installation instructions at:
https://github.com/volatilityfoundation/volatility3

## 3. Install the dwarf2json Tool
-  Use the `dwarf2json` tool to generate Python symbol tables suitable for Linux and Python internals.
- Clone the dwarf2json repository, place it in the Volaitlity 3 directory, and follow the installation instructions at:
 https://github.com/volatilityfoundation/dwarf2json

 ### 4. Generate Symbol Tables
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

### 5. Place the Plugins:
 #### For Linux Plugins:
   Copy the  plugins and the Core scripts to the Volatility Linux plugin directory (e.g., ```/path/to/volatility3/volatility3/framework/plugins/linux/```).
 #### For Windows Plugins:
  Copy the  plugins and the Core scripts to the Volatility Windows plugin directory (e.g., ```/path/to/volatility3/volatility3/framework/plugins/windows/```).
   

---

# Usage
### Generate a full SBOM from a memory dump:
``` python3 vol.py -f dump.vmem linux.mem_sbom.MEM_SBOM --pid 22162```
### Generate SBOM with dependency graph:
bash python3 vol.py -f dump.vmem linux.mem_sbom.MEM_SBOM --pid 22162 --dep

### Skip sournces depends on the investigator's requirments:
- Skip heap scanning (fastest)
```python3 vol.py -f dump.vmem linux.mem_sbom.MEM_SBOM --pid 22162 --skip-heap```

- Skip GC walking
```python3 vol.py -f dump.vmem linux.mem_sbom.MEM_SBOM --pid 22162 --skip-gc```

- Interpreter-only (fastest, may miss hidden modules)
```python3 vol.py -f dump.vmem linux.mem_sbom.MEM_SBOM --pid 22162 --skip-gc --skip-heap```

### Run individual components for targeted analysis:
- Extract all modules across the process tree
```python3 vol.py -f dump.vmem linux.module_extractor.Module_Extractor --pid 22162```

-  Walk GC lists for a single process
```python3 vol.py -f dump.vmem linux.py_gc.Py_GC --pid 22162```

-  Scan heap for hidden/unlinked modules
```python3 vol.py -f dump.vmem linux.py_heap.Py_Heap --pid 22162```

-  Dump interpreter state (sys.modules)
```python3 vol.py -f dump.vmem linux.py_interpreter.Py_Interpreter --pid 22162```

---
# Repository Structure

The repository is organized into several directories that contain the MEM-SBOM plugins, supporting components, and example outputs.
## Core

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


   
