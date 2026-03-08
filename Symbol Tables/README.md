
#### Python Symbol Tables for Volatility 3

##### What Are Python Symbol Tables?

The Python memory forensics plugins require **Python symbol tables** (`.json` files) to parse Python runtime data structures from memory dumps. These files contain type definitions and structure layouts (e.g., `PyObject`, `PyDictObject`, `PyFrameObject`, `PyCodeObject`) extracted from **debug builds** of the CPython interpreter using [`dwarf2json`](https://github.com/volatilityfoundation/dwarf2json).

- The symbol table **must match** the Python version of the process captured in the memory dump.
- Without the correct symbol table, the plugins cannot accurately reconstruct Python objects.

---

##### Pre-Generated Symbol Tables

| File | Python Version |
|------|---------------|
| `python38.json` | Python 3.8.10 |
| `python39.json` | Python 3.9.19 |
| `python310.json` | Python 3.10.14 |
| `python311.json` | Python 3.11.9 |
| `python312.json` | Python 3.12.4 |
| `python313.json` | Python 3.13.0 |

---

##### Installation

 1. Create the required directory inside your Volatility 3 installation:
``````mkdir -p /path/to/volatility3/volatility3/framework/symbols/generic/types/python/```
 2. Copy the `.json` symbol files into the `python/` folder:
`````cp *.json /path/to/volatility3/volatility3/framework/symbols/generic/types/python/```

---

##### Generating Symbol Tables for Other Python Versions

If the target memory dump contains a Python version not covered by the pre-generated files, follow one of the methods below.

###### Prerequisites

- A Linux system (Ubuntu recommended)
- [`dwarf2json`](https://github.com/volatilityfoundation/dwarf2json) compiled and ready to use
- Build dependencies:
````sudo apt install -y make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev```

---

###### Option A: Using System Packages (Ubuntu Default Python Only)

For the Python version that ships with your Ubuntu (e.g., Python 3.8 on Ubuntu 20.04):

 1. Install the debug build package:
    - Command: ```sudo apt install libpython3.*-dbg```
    - Example: for Python 3.8: ```sudo apt install libpython3.8-dbg```
    - Note: This method only works for Python versions available in your distribution's package repository.
 2. Locate the debug shared library:
    - Command: ```find /usr/lib -name "libpython3.*d.so*"```
    - Example output: ```/usr/lib/x86_64-linux-gnu/libpython3.8d.so.1.0```
 3. Generate the symbol file:
    - Command: ```./dwarf2json linux --elf /path/to/libpython3.*d.so.1.0 > output_filename.json```
    - Example: ```./dwarf2json linux --elf /usr/lib/x86_64-linux-gnu/libpython3.8d.so.1.0 > python38.json```
 4. Place the file in Volatility 3:
    - Create a folder (`python`) in: ```/path/to/volatility3/volatility3/framework/symbols/generic/types/```
    - Place the `.json` file in the `python` folder

---

###### Option B: Using pyenv (Any Python Version)

For Python versions **not available** through system packages, use [pyenv](https://github.com/pyenv/pyenv) to build debug versions from source.

**Step 1: Install pyenv**

 1. Run the installer:
```curl https://pyenv.run | bash```
 2. Add the following to `~/.bashrc`:
```
    export PYENV_ROOT="$HOME/.pyenv"
    export PATH="$PYENV_ROOT/bin:$PATH"
    eval "$(pyenv init --path)"
    eval "$(pyenv init -)"
````
 3. Reload your shell:
````source ~/.bashrc```

**Step 2: Build Python with Debug Symbols**

 1. Install the desired Python version with debug flags:
    - Command: ```PYTHON_CONFIGURE_OPTS="--with-pydebug --enable-shared" pyenv install <version>```
    - Example: ```PYTHON_CONFIGURE_OPTS="--with-pydebug --enable-shared" pyenv install 3.10.14```
    - Note: Both `--with-pydebug` and `--enable-shared` are **required**. `--with-pydebug` includes DWARF debug symbols, and `--enable-shared` produces the `.so` shared library needed by `dwarf2json`.

**Step 3: Locate the Debug Library**

 1. Find the debug shared library:
    - Command: ```find ~/.pyenv/versions/<version>/ -name "libpython*d.so*"```
    - Example: ```find ~/.pyenv/versions/3.10.14/ -name "libpython*d.so*"```
    - Expected output:
````
      /home/user/.pyenv/versions/3.10.14/lib/libpython3.10d.so
      /home/user/.pyenv/versions/3.10.14/lib/libpython3.10d.so.1.0
`````

**Step 4: Generate the Symbol File**

 1. Run `dwarf2json` against the `.so.1.0` file:
    - Command: ```./dwarf2json linux --elf /path/to/libpython3.*d.so.1.0 > output_filename.json```
    - Example: ```./dwarf2json linux --elf ~/.pyenv/versions/3.10.14/lib/libpython3.10d.so.1.0 > python310.json```

**Step 5: Install the Symbol File**

 1. Create the folder (if it doesn't exist): ```mkdir -p /path/to/volatility3/volatility3/framework/symbols/generic/types/python/```
 2. Place the file: ```cp python310.json /path/to/volatility3/volatility3/framework/symbols/generic/types/python/```

---

##### Troubleshooting

 1. **"Unable to find symbol table" error:**
    - Ensure the `.json` file is placed in the correct directory: ```volatility3/framework/symbols/generic/types/python/```
 2. **Plugin fails to extract expected data:**
    - Verify that the symbol table matches the exact Python version in the memory dump.
    - Note: Minor version differences (e.g., 3.10.12 vs 3.10.14) are generally compatible, but major/minor mismatches (e.g., 3.10 vs 3.11) will cause failures due to internal structure changes.
 3. **`dwarf2json` produces an empty or very small file:**
    - Confirm you are using the **debug** library (```libpython3.Xd.so.1.0``` — note the `d` suffix).
    - Non-debug libraries lack the DWARF information needed for symbol extraction.
 4. **pyenv build missing debug `.so` file:**
    - Ensure you used both `--with-pydebug` and `--enable-shared` flags.

