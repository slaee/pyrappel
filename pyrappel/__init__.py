"""PyRappel modular package."""

# Re-export commonly used components for convenience
from .config import settings

"""
PyRappel package

This package provides a modular, maintainable structure for the PyRappel
interactive assembler using ptrace. It exposes a simple Facade via
`pyrappel.facade.Rappel` and a CLI via `pyrappel.cli.main`.
"""

__all__ = [
    "config",
    "elf",
    "exec_file",
    "arch",
    "keystone_wrapper",
    "ptrace_wrapper",
    "facade",
    "cli",
]


