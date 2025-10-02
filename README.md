# PyRappel

PyRappel is an interactive assembler with ptrace support - a Python version of the original [rappel](https://github.com/yrp604/rappel) tool.

## Installation

### From PyPI (recommended)
```bash
pip install pyrappel
```

### From source
```bash
git clone <repository-url>
cd pyrappelv2
pip install .
```

### Development installation
```bash
git clone <repository-url>
cd pyrappelv2
pip install -e .[dev]
```

## Usage

After pip installation, PyRappel is automatically installed as a system-wide executable. You can run it from anywhere in your terminal:

```bash
pyrappel -h
```

The `pyrappel` command is automatically:
- Installed in your system PATH (e.g., `/usr/local/bin/pyrappel` or `~/.local/bin/pyrappel`)
- Made executable
- Available from any directory

### Command line options:
- `-a, --arch`: Target architecture (x86 or x64, default: x64)
- `-s, --start-addr`: Start virtual address for code execution (default: 0x400000)
- `-A, --all-regs`: Display all available registers (including FP/SSE)
- `-v, --verbose`: Enable verbose output

### Examples:
```bash
# Start with x64 architecture (default)
pyrappel

# Start with x86 architecture
pyrappel -a x86

# Start with custom start address
pyrappel -s 0x10000000

# Show all registers
pyrappel -A
```

## Requirements

- Python 3.11+
- Linux (ptrace support required)
- Dependencies are automatically installed via pip

## Development

The package uses modern Python packaging with `pyproject.toml`. For development:

```bash
pip install -e .[dev]
```

## Original Project

This is a Python reimplementation of the original C version: [Rappel](https://github.com/yrp604/rappel)
