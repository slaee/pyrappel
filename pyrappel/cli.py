import sys
import argparse
import logging
from .config import settings, PAGE_SIZE
from .ui import Rappel


def main(argv=None):
    parser = argparse.ArgumentParser(description="Interactive Assembler with Ptrace")
    parser.add_argument('-a', '--arch', type=str, default='x64', choices=['x86', 'x64'], help='Target architecture (x86 or x64)')
    parser.add_argument('-s', '--start-addr', type=str, default=f"{settings['start_addr']:#x}", help='Start virtual address for code execution (e.g., 0x400000)')
    parser.add_argument('-A', '--all-regs', action='store_true', default=False, help='Display all available registers (including FP/SSE)')
    parser.add_argument('-v','--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args(argv)

    settings['arch'] = args.arch
    try:
        settings['start_addr'] = int(args.start_addr, 0)
    except ValueError:
        logging.error(f"[-] Invalid start address format: '{args.start_addr}'. Use hex (0x...) or decimal.")
        sys.exit(1)
    settings['all_regs'] = args.all_regs

    print("--- PyRappel Interactive Assembler ---")
    print(f"Architecture: {settings['arch']}")
    print(f"Start Address: {settings['start_addr']:#x}")
    print(f"Show All Regs: {settings['all_regs']}")
    print(f"Page Size: {PAGE_SIZE}")
    print("Author: @slaee")
    print("-" * 38)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)

    rappel = Rappel(settings['arch'])
    rappel.interact()


if __name__ == '__main__':
    main()


