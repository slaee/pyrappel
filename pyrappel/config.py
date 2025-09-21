import os


# region Settings
user_path = os.getenv('HOME')

settings = {
    # 'path': f'{user_path}/.rappel/exe',
    'path': 'bin',  # Use a local bin directory for temporary files
    'start_addr': 0x400000,
    'arch': 'x64',  # Default arch
    'all_regs': False,  # Default to showing only common regs
}

# Ensure bin directory exists
if not os.path.exists(settings['path']):
    os.makedirs(settings['path'])
# endregion


# region Constants
PAGE_SIZE = os.sysconf('SC_PAGE_SIZE')
TRAP = 0xcc  # INT3 instruction byte

# Formatting and ANSI colors used in register dumps
REGFMT64 = "{:016x}"
REGFMT32 = "{:08x}"
REGFMT16 = "{:04x}"
REGFMT8 = "{:02x}"

RED = "\x1b[1;31m"
RST = "\x1b[0m"
# endregion


