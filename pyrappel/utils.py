RED = "\x1b[1;31m"
RST = "\x1b[0m"

REGFMT64 = "{:016x}"
REGFMT32 = "{:08x}"
REGFMT16 = "{:04x}"
REGFMT8  = "{:02x}"

def highlight_equal(value_str, changed):
    return value_str if not changed else f"{RED}{value_str}{RST}"

def print_bit(name, y_bit, z_bit, trailer):
    if y_bit == z_bit:
        print(f"{name}{y_bit}", end="")
    else:
        print(f"{RED}{name}{y_bit}{RST}", end="")
    print(trailer, end="")


