# region IMPORTS
import os
import sys
import ctypes.util
import signal
import stat
import tempfile
import keystone
import argparse
import struct
import errno
import logging

from ctypes import *
# endregion





# region RAPPEL SETTINGS
user_path = os.getenv('HOME')

settings = {
    # 'path': f'{user_path}/.rappel/exe',
    'path': 'bin', # Use a local bin directory for temporary files
    'start_addr': 0x400000,
    'arch': 'x64', # Default arch
    'all_regs': False, # Default to showing only common regs
}

# Ensure bin directory exists
if not os.path.exists(settings['path']):
    os.makedirs(settings['path'])
# endregion





# region BINARY GENERATION
# Page size of the system - typically 4096
PAGE_SIZE   = os.sysconf('SC_PAGE_SIZE') # Use system's page size

# elf-em.h

# EM values for e_machine
EM_X86_64   = 62
EM_386      = 3


# elf.h

# 32-bit ELF base types
Elf32_Addr  = c_uint32  # __u32
Elf32_Half  = c_uint16  # __u16
Elf32_Off   = c_uint32  # __u32
Elf32_Sword = c_int32   # __s32
Elf32_Word  = c_uint32  # __u32

# 64-bit ELF base types
Elf64_Addr  = c_uint64  # __u64
Elf64_Half  = c_uint16  # __u16
Elf64_SHalf = c_int16   # __s16
Elf64_Off   = c_uint64  # __u64
Elf64_Sword = c_int32   # __s32
Elf64_Word  = c_uint32  # __u32
Elf64_Xword = c_uint64  # __u64
Elf64_Sxword = c_int64  # __s64

# These constants define the different elf file types
ET_EXEC = 2

# These constants are for the segment types stored in the image headers
PT_LOAD = 1


EI_NIDENT = 16

class Elf32_Ehdr(Structure):
    _fields_ = [
        ('e_ident', c_uint8 * EI_NIDENT), # Elf32_Ehdr.e_ident[EI_NIDENT]
        ('e_type', Elf32_Half),
        ('e_machine', Elf32_Half),
        ('e_version', Elf32_Word),
        ('e_entry', Elf32_Addr),
        ('e_phoff', Elf32_Off),
        ('e_shoff', Elf32_Off),
        ('e_flags', Elf32_Word),
        ('e_ehsize', Elf32_Half),
        ('e_phentsize', Elf32_Half),
        ('e_phnum', Elf32_Half),
        ('e_shentsize', Elf32_Half),
        ('e_shnum', Elf32_Half),
        ('e_shstrndx', Elf32_Half)
    ]

class Elf64_Ehdr(Structure):
    _fields_ = [
        ('e_ident', c_uint8 * EI_NIDENT), # Elf64_Ehdr.e_ident[EI_NIDENT]
        ('e_type', Elf64_Half),
        ('e_machine', Elf64_Half),
        ('e_version', Elf64_Word),
        ('e_entry', Elf64_Addr),
        ('e_phoff', Elf64_Off),
        ('e_shoff', Elf64_Off),
        ('e_flags', Elf64_Word),
        ('e_ehsize', Elf64_Half),
        ('e_phentsize', Elf64_Half),
        ('e_phnum', Elf64_Half),
        ('e_shentsize', Elf64_Half),
        ('e_shnum', Elf64_Half),
        ('e_shstrndx', Elf64_Half)
    ]

# These constants define the permissions on sections in the program header, p_flags.
PF_R = 0x4
PF_W = 0x2
PF_X = 0x1

class Elf32_Phdr(Structure):
    _fields_ = [
        ('p_type', Elf32_Word),
        ('p_offset', Elf32_Off),
        ('p_vaddr', Elf32_Addr),
        ('p_paddr', Elf32_Addr),
        ('p_filesz', Elf32_Word),
        ('p_memsz', Elf32_Word),
        ('p_flags', Elf32_Word),
        ('p_align', Elf32_Word)
    ]

class Elf64_Phdr(Structure):
    _fields_ = [
        ('p_type', Elf64_Word),
        ('p_flags', Elf64_Word),
        ('p_offset', Elf64_Off),    # Segment file offset
        ('p_vaddr', Elf64_Addr),    # Segment virtual address
        ('p_paddr', Elf64_Addr),    # Segment physical address
        ('p_filesz', Elf64_Xword),  # Segment size in file
        ('p_memsz', Elf64_Xword),   # Segment size in memory
        ('p_align', Elf64_Xword)    # Segment alignment, file & memory
    ]

# EI_MAG - Magic number
ELFMAG0 = 0x7f
ELFMAG1 = ord('E')
ELFMAG2 = ord('L')
ELFMAG3 = ord('F')

# EI_CLASS
ELFCLASS32 = 1
ELFCLASS64 = 2

# e_ident[EI_DATA]
ELFDATA2LSB = 1

# e_version, EI_VERSION
EV_CURRENT = 1

# e_ident[EI_OSABI]
ELFOSABI_NONE = 0 # Often ELFOSABI_SYSV (0) or ELFOSABI_LINUX (3)

TRAP = 0xcc # INT3 instruction byte

class ELF:
    def __init__(self, arch, out=None, start=None, code=None, code_size=None):
        self.arch = arch
        self.out = out
        self.start = start if start is not None else settings['start_addr']
        self.code = code
        self.code_size = code_size if code_size is not None else PAGE_SIZE

    def gen_elf(self):
        """
        Generates a minimal ELF executable containing the provided code.
        The layout aims for simplicity:
        Page 1: ELF Header, Program Header(s)
        Page 2 onwards: Code/Data Segment(s)
        """
        if self.arch == 'x86':
            return self.__gen_elf32()
        elif self.arch == 'x64':
            return self.__gen_elf64()
        else:
            raise ValueError(f'Unsupported architecture: {self.arch}')

    def __gen_elf32(self):
        ehdr_size = sizeof(Elf32_Ehdr)
        phdr_size = sizeof(Elf32_Phdr)
        num_phdrs = 1 # Only one PT_LOAD segment for code

        # Ensure start address and alignment calculations are correct
        # We want the segment containing self.start to be loaded correctly.
        # The virtual address (p_vaddr) and file offset (p_offset) must be congruent modulo page size.
        page_mask = PAGE_SIZE - 1
        pg_offset = self.start & page_mask # Offset of start address within its page
        segment_vaddr = self.start - pg_offset # Start of the virtual page containing self.start
        segment_offset = PAGE_SIZE # Place code starting from the second page in the file

        # Calculate total size needed for headers + code (including padding for page alignment)
        header_total_size = ehdr_size + phdr_size * num_phdrs
        # Ensure headers fit within the first page, leave rest for padding if needed
        if header_total_size > PAGE_SIZE:
            raise ValueError("ELF headers too large for a single page")

        # Calculate file size for the PT_LOAD segment
        # It starts pg_offset bytes into the mapped page and contains self.code_size bytes
        segment_filesz = pg_offset + self.code_size
        segment_memsz = segment_filesz # For simplicity, memsz == filesz

        # Total file size: first page for headers, then the segment data
        # The segment data starts at segment_offset (PAGE_SIZE)
        # The size of data written is segment_filesz
        total_file_size = segment_offset + segment_filesz

        # Create buffer for the entire ELF file
        e = create_string_buffer(total_file_size)
        # Initialize with TRAP, especially the code area
        memset(e, 0, total_file_size) # Zero out headers first
        # Fill code area with TRAP
        memset(addressof(e) + segment_offset + pg_offset, TRAP, self.code_size)

        # ELF Header (Ehdr)
        ehdr: Elf32_Ehdr = cast(e, POINTER(Elf32_Ehdr)).contents
        ehdr.e_ident[0:4] = bytes([ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3])
        ehdr.e_ident[4] = ELFCLASS32
        ehdr.e_ident[5] = ELFDATA2LSB
        ehdr.e_ident[6] = EV_CURRENT
        ehdr.e_ident[7] = ELFOSABI_NONE # Or ELFOSABI_SYSV / ELFOSABI_LINUX
        # ehdr.e_ident[8:16] are padding, already zeroed
        ehdr.e_type = ET_EXEC
        ehdr.e_machine = EM_386
        ehdr.e_version = EV_CURRENT
        ehdr.e_entry = self.start # Entry point address
        ehdr.e_phoff = ehdr_size # Program header table offset
        ehdr.e_shoff = 0 # No section headers
        ehdr.e_flags = 0 # No architecture-specific flags
        ehdr.e_ehsize = ehdr_size
        ehdr.e_phentsize = phdr_size
        ehdr.e_phnum = num_phdrs
        ehdr.e_shentsize = 0
        ehdr.e_shnum = 0
        ehdr.e_shstrndx = 0

        # Program Header (Phdr) for the code segment
        phdr_address = addressof(e) + ehdr.e_phoff
        phdr: Elf32_Phdr = cast(phdr_address, POINTER(Elf32_Phdr)).contents
        phdr.p_type = PT_LOAD
        phdr.p_flags = PF_X | PF_R | PF_W # Executable, Readable, Writable (for ptrace POKE)
        phdr.p_offset = segment_offset # Segment data starts at PAGE_SIZE offset in file
        phdr.p_vaddr = segment_vaddr # Segment loads at page-aligned virtual address
        phdr.p_paddr = 0 # Physical address (ignored on Linux)
        phdr.p_filesz = segment_filesz # Size of segment data in file
        phdr.p_memsz = segment_memsz # Size of segment in memory
        phdr.p_align = PAGE_SIZE # Segment alignment (must be power of 2, typically PAGE_SIZE)

        # Copy provided initial code (if any) into the ELF buffer at the correct position
        if self.code:
             code_dest_offset = segment_offset + pg_offset
             # Ensure we don't copy more than allocated code_size
             copy_size = min(len(self.code), self.code_size)
             memmove(addressof(e) + code_dest_offset, self.code, copy_size)


        self.out = e.raw
        return total_file_size

    def __gen_elf64(self):
        ehdr_size = sizeof(Elf64_Ehdr)
        phdr_size = sizeof(Elf64_Phdr)
        num_phdrs = 1

        page_mask = PAGE_SIZE - 1
        pg_offset = self.start & page_mask
        segment_vaddr = self.start - pg_offset
        segment_offset = PAGE_SIZE

        header_total_size = ehdr_size + phdr_size * num_phdrs
        if header_total_size > PAGE_SIZE:
            raise ValueError("ELF headers too large for a single page")

        segment_filesz = pg_offset + self.code_size
        segment_memsz = segment_filesz

        total_file_size = segment_offset + segment_filesz

        e = create_string_buffer(total_file_size)
        memset(e, 0, total_file_size)
        memset(addressof(e) + segment_offset + pg_offset, TRAP, self.code_size)


        ehdr: Elf64_Ehdr = cast(e, POINTER(Elf64_Ehdr)).contents
        ehdr.e_ident[0:4] = bytes([ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3])
        ehdr.e_ident[4] = ELFCLASS64
        ehdr.e_ident[5] = ELFDATA2LSB
        ehdr.e_ident[6] = EV_CURRENT
        ehdr.e_ident[7] = ELFOSABI_NONE
        ehdr.e_type = ET_EXEC
        ehdr.e_machine = EM_X86_64
        ehdr.e_version = EV_CURRENT
        ehdr.e_entry = self.start
        ehdr.e_phoff = ehdr_size
        ehdr.e_shoff = 0
        ehdr.e_flags = 0
        ehdr.e_ehsize = ehdr_size
        ehdr.e_phentsize = phdr_size
        ehdr.e_phnum = num_phdrs
        ehdr.e_shentsize = 0
        ehdr.e_shnum = 0
        ehdr.e_shstrndx = 0

        phdr_address = addressof(e) + ehdr.e_phoff
        phdr: Elf64_Phdr = cast(phdr_address, POINTER(Elf64_Phdr)).contents
        phdr.p_type = PT_LOAD
        phdr.p_flags = PF_X | PF_R | PF_W # Need Writable for PTRACE_POKEDATA
        phdr.p_offset = segment_offset
        phdr.p_vaddr = segment_vaddr
        phdr.p_paddr = 0
        phdr.p_filesz = segment_filesz
        phdr.p_memsz = segment_memsz
        phdr.p_align = PAGE_SIZE

        if self.code:
             code_dest_offset = segment_offset + pg_offset
             copy_size = min(len(self.code), self.code_size)
             memmove(addressof(e) + code_dest_offset, self.code, copy_size)

        self.out = e.raw
        return total_file_size
# endregion





# region EXECUTABLE FILE WRAPPER
class ExecutableFile:
    """Wraps a file descriptor for an executable, managing its path and temp status."""
    def __init__(self, fd, path, is_temp):
        if not isinstance(fd, int) or fd < 0:
            raise ValueError("Invalid file descriptor provided.")
        self._fd = fd
        self.path = path
        self.is_temp = is_temp
        # print(f"[Debug] Created ExecutableFile: fd={self._fd}, path={self.path}, is_temp={self.is_temp}")

    def fileno(self):
        """Return the integer file descriptor."""
        if self._fd < 0:
             raise ValueError("File descriptor is closed or invalid.")
        return self._fd

    def close(self):
         """Close the underlying file descriptor."""
         if self._fd >= 0:
             # print(f"[Debug] Closing fd {self._fd} for {self.path}")
             try:
                 os.close(self._fd)
             except OSError as e:
                  logging.error(f"[-] Warning: Failed to close fd {self._fd} for {self.path}: {e}")
             finally:
                 self._fd = -1 # Mark as closed

    def __del__(self):
         # Ensure fd is closed if the object is garbage collected, although explicit cleanup is preferred.
         # Avoid printing during __del__ if possible.
         if self._fd >= 0:
              try:
                  os.close(self._fd)
              except OSError:
                  pass # Ignore errors during GC cleanup
              self._fd = -1

    @property
    def temp_path(self):
         """Return the path if it's temporary, else None."""
         return self.path if self.is_temp else None

# endregion





# region RAPPEL EXE WRITER
class RappelExe:
    @staticmethod
    def write(data, path=None) -> ExecutableFile | None: # Add type hint
        """Writes data to a file, makes it executable, and returns an ExecutableFile object."""
        is_temp = False
        file_path = path
        fd = -1
        ro_fd = -1 # Initialize ro_fd

        try:
            if path is None:
                # Create a temporary file
                is_temp = True
                temp_dir = settings.get('path', '/tmp')
                if not os.path.isdir(temp_dir):
                    os.makedirs(temp_dir, exist_ok=True)

                # Use a context manager for the temporary file creation/writing if possible,
                # but mkstemp gives fd directly which we need.
                fd, file_path = tempfile.mkstemp(prefix='rappel-exe.', dir=temp_dir)
                if fd < 0:
                    raise OSError(f"Failed to create temporary file: {os.strerror(ctypes.get_errno())}")

                try:
                    bytes_written = os.write(fd, data)
                    if bytes_written != len(data):
                        raise IOError(f"Incomplete write to temporary file '{file_path}'")
                    os.fchmod(fd, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
                finally:
                    # Ensure write fd is closed even if chmod fails
                    if fd >= 0:
                        os.close(fd)
                        fd = -1 # Mark as closed
            else:
                # Write to a specific path
                file_path = path
                try:
                    # Open with explicit permissions, truncate if exists
                    # Permissions: rwxr-xr-x after chmod below
                    fd = os.open(file_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, stat.S_IRWXU)
                except OSError as e:
                    if e.errno == errno.EACCES: # Permission denied
                        try:
                           logging.error(f"[-] Permission denied for '{file_path}', attempting to delete and recreate.")
                           os.unlink(file_path)
                           fd = os.open(file_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, stat.S_IRWXU)
                        except Exception as inner_e:
                           raise OSError(f"Failed to open '{file_path}' after delete attempt: {inner_e}") from e
                    else:
                       raise

                if fd < 0:
                    raise OSError(f"Failed to open '{file_path}' for writing: {os.strerror(ctypes.get_errno())}")

                try:
                    bytes_written = os.write(fd, data)
                    if bytes_written != len(data):
                        raise IOError(f"Incomplete write to file '{file_path}'")
                    # Set permissions after writing
                    os.fchmod(fd, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
                finally:
                    if fd >= 0:
                        os.close(fd)
                        fd = -1 # Mark as closed

            # Reopen the file read-only with O_CLOEXEC
            ro_fd = os.open(file_path, os.O_RDONLY | os.O_CLOEXEC)
            if ro_fd < 0:
                err = ctypes.get_errno()
                # If reopening failed, try to clean up the potentially created file
                if os.path.exists(file_path):
                    if is_temp:
                        try: os.unlink(file_path)
                        except OSError: pass
                    else:
                        logging.error(f"[-] Warning: Executable written to '{file_path}' but failed to reopen read-only.")
                raise OSError(err, f"Failed to reopen '{file_path}' read-only: {os.strerror(err)}")

            # Return the wrapper object
            return ExecutableFile(ro_fd, file_path, is_temp)

        except Exception as e:
            logging.error(f"[-] Error writing executable: {e}")
            # Ensure FDs are closed on error
            if fd >= 0:
                try: os.close(fd)
                except OSError: pass
            if ro_fd >= 0: # If reopen succeeded but wrapper failed somehow
                 try: os.close(ro_fd)
                 except OSError: pass
            # Clean up temp file if created but failed later
            if is_temp and file_path and os.path.exists(file_path):
                try: os.unlink(file_path)
                except OSError: pass
            return None # Indicate failure


    @staticmethod
    def cleanup(exe_file_obj: ExecutableFile | None):
        """Cleans up the temporary file (if any) and closes the fd."""
        if exe_file_obj is None:
             return

        # Close the file descriptor first
        exe_file_obj.close() # Uses the wrapper's close method

        # Delete the file if it was temporary
        temp_path = exe_file_obj.temp_path # Use the property
        if temp_path:
            # print(f"[Debug] Cleaning up temporary file: {temp_path}")
            try:
                os.unlink(temp_path)
                logging.info(f"[+] Cleaned up temporary file: {temp_path}") # Optional debug msg
            except FileNotFoundError:
                pass # Already deleted, ignore
            except OSError as e:
                logging.warning(f"[-] Warning: Failed to clean up temporary file '{temp_path}': {e}")

# endregion





# region UTIL FUNCTIONS
REGFMT64 = "{:016x}"  # Equivalent to "%016llx" or "%016lx" in C (64-bit)
REGFMT32 = "{:08x}"   # Equivalent to "%08x" in C (32-bit)
REGFMT16 = "{:04x}"   # Equivalent to "%04x" in C (16-bit)
REGFMT8  = "{:02x}"   # Equivalent to "%02x" in C (8-bit)

RED = "\x1b[1;31m"    # ANSI escape code for bold red text
RST = "\x1b[0m"       # ANSI reset code

def dump_reg64(x_name, y, z):
    """
    Prints the value of a 64-bit register attribute (y.x_name).
    Highlights in red if it differs from the old value (z.x_name).
    """
    try:
        y_value = getattr(y, x_name)
        z_value = getattr(z, x_name)
    except AttributeError:
        print(f"<ERR:{x_name}>", end="")
        return

    if y_value == z_value:
        print(REGFMT64.format(y_value), end="")
    else:
        print(f"{RED}{REGFMT64.format(y_value)}{RST}", end="")

def dump_reg64_arr(x_name, index, y, z):
    """Prints a 64-bit value from an array attribute (y.x_name[index])."""
    try:
        y_arr = getattr(y, x_name)
        z_arr = getattr(z, x_name)
        # Ensure index is within bounds
        if index < 0 or index >= len(y_arr) or index >= len(z_arr):
             print("<ERR:IDX>", end="")
             return
        y_value = y_arr[index]
        z_value = z_arr[index]
    except (AttributeError, IndexError, TypeError):
        print(f"<ERR:{x_name}[{index}]>", end="")
        return

    if y_value == z_value:
        print(REGFMT64.format(y_value), end="")
    else:
        print(f"{RED}{REGFMT64.format(y_value)}{RST}", end="")

def print_reg64(header, x_name, y, z, trailer):
    """Prints header, dumps 64-bit register value, prints trailer."""
    print(header, end="")
    dump_reg64(x_name, y, z)
    print(trailer, end="")

def dump_reg32(x_name, y, z):
    """Prints the value of a 32-bit register attribute (y.x_name)."""
    try:
        y_value = getattr(y, x_name)
        z_value = getattr(z, x_name)
    except AttributeError:
        print(f"<ERR:{x_name}>", end="")
        return

    if y_value == z_value:
        print(REGFMT32.format(y_value), end="")
    else:
        print(f"{RED}{REGFMT32.format(y_value)}{RST}", end="")

def dump_reg32_arr(x_name, index, y, z):
    """Prints a 32-bit value from an array attribute (y.x_name[index])."""
    try:
        y_arr = getattr(y, x_name)
        z_arr = getattr(z, x_name)
        if index < 0 or index >= len(y_arr) or index >= len(z_arr):
             print("<ERR:IDX>", end="")
             return
        y_value = y_arr[index]
        z_value = z_arr[index]
    except (AttributeError, IndexError, TypeError):
        print(f"<ERR:{x_name}[{index}]>", end="")
        return

    if y_value == z_value:
        print(REGFMT32.format(y_value), end="")
    else:
        print(f"{RED}{REGFMT32.format(y_value)}{RST}", end="")

def print_reg32(header, x_name, y, z, trailer):
    """Prints header, dumps 32-bit register value, prints trailer."""
    print(header, end="")
    dump_reg32(x_name, y, z)
    print(trailer, end="")

def dump_reg16(x_name, y, z):
    """Prints the value of a 16-bit register attribute (y.x_name)."""
    try:
        y_value = getattr(y, x_name)
        z_value = getattr(z, x_name)
    except AttributeError:
        print(f"<ERR:{x_name}>", end="")
        return

    if y_value == z_value:
        print(REGFMT16.format(y_value), end="")
    else:
        print(f"{RED}{REGFMT16.format(y_value)}{RST}", end="")

def print_reg16(header, x_name, y, z, trailer):
    """Prints header, dumps 16-bit register value, prints trailer."""
    print(header, end="")
    dump_reg16(x_name, y, z)
    print(trailer, end="")

def dump_reg8(x_name, y, z):
    """Prints the value of an 8-bit register attribute (y.x_name)."""
    try:
        y_value = getattr(y, x_name)
        z_value = getattr(z, x_name)
    except AttributeError:
        print(f"<ERR:{x_name}>", end="")
        return

    if y_value == z_value:
        print(REGFMT8.format(y_value), end="")
    else:
        print(f"{RED}{REGFMT8.format(y_value)}{RST}", end="")

def print_reg8(header, x_name, y, z, trailer):
    """Prints header, dumps 8-bit register value, prints trailer."""
    print(header, end="")
    dump_reg8(x_name, y, z)
    print(trailer, end="")

def print_bit(name, y_bit, z_bit, trailer):
    """Prints a flag bit value (y_bit), highlights if changed from z_bit."""
    if y_bit == z_bit:
        print(f"{name}{y_bit}", end="")
    else:
        print(f"{RED}{name}{y_bit}{RST}", end="")
    print(trailer, end="")
# endregion





# region ARCH STRUCTURES

# Define structures based on <sys/user.h> for the target architecture(s)
# These might need adjustment depending on the exact Linux kernel version/distro
# Using standard names for better compatibility

# --- x86 (32-bit) ---
class user_fpregs_struct_x86(Structure):
    _fields_ = [
        ('cwd', c_uint32),
        ('swd', c_uint32),
        ('twd', c_uint32),
        ('fip', c_uint32),
        ('fcs', c_uint32),
        ('foo', c_uint32),
        ('fos', c_uint32),
        ('st_space', c_uint32 * 20), # 8 * 10 bytes = 80 bytes = 20 dwords
    ]

class user_regs_struct_x86(Structure):
    _fields_ = [
        ('ebx', c_uint32),
        ('ecx', c_uint32),
        ('edx', c_uint32),
        ('esi', c_uint32),
        ('edi', c_uint32),
        ('ebp', c_uint32),
        ('eax', c_uint32),
        ('xds', c_uint32), # selector in low 16 bits
        ('xes', c_uint32),
        ('xfs', c_uint32),
        ('xgs', c_uint32),
        ('orig_eax', c_uint32),
        ('eip', c_uint32),
        ('xcs', c_uint32),
        ('eflags', c_uint32),
        ('esp', c_uint32),
        ('xss', c_uint32)
    ]

# FXSAVE structure (used for PTRACE_GETREGSET with NT_PRXFPREG on x86)
# Size is 512 bytes, alignment 16
class user_fpxregs_struct_x86(Structure):
     _pack_ = 16 # Ensure correct alignment if needed, though ctypes might handle it
     _fields_ = [
        ('cwd', c_uint16),
        ('swd', c_uint16),
        ('twd', c_uint16), # FTW (tag word)
        ('fop', c_uint16),
        ('fip', c_uint32), # 32-bit IP or 64-bit? Check sys/user.h. Often union/struct
        ('fcs', c_uint32), # Needs careful checking against system headers
        # ('fip_rip', c_uint64), # Alternative if 64-bit IP used in FXSAVE
        # ('fcs_fselector', c_uint16), # Alternative structure part
        ('foo', c_uint32), # FPU operand pointer offset
        ('fos', c_uint32), # FPU operand pointer segment selector
        # ('foo_rdp', c_uint64), # Alternative if 64-bit RDP used in FXSAVE
        # ('fos_fopcode', c_uint16), # Alternative structure part
        ('mxcsr', c_uint32),
        ('mxcsr_mask', c_uint32),
        ('st_space', c_uint8 * 128),  # 8 * 16 bytes (ST0-ST7 + padding)
        ('xmm_space', c_uint8 * 128), # 8 * 16 bytes (XMM0-XMM7)
        ('padding', c_uint8 * (512 - 16 - 8 - 8 - 4 - 4 - 128 - 128)), # Adjust padding size based on exact field sizes used
        # The above padding calculation is complex and error-prone.
        # A safer way is often to define a large byte array and cast parts,
        # or rely on system header definitions if possible (e.g., via cffi).
        # For simplicity, let's assume a fixed size and hope ctypes alignment works.
        # ('padding', c_uint8 * 224) # Based on common layout approx. Recheck this.
        ('__padding_actual', c_uint8 * (512 - (2*6 + 4*4 + 128 + 128))) # Recalculate padding
     ]
     # Ensure total size is 512 bytes
# print("Size of user_fpxregs_struct_x86:", sizeof(user_fpxregs_struct_x86)) # Check size at runtime

# --- x86_64 (64-bit) ---
class user_regs_struct_x64(Structure):
    _fields_ = [
        ('r15', c_ulonglong),
        ('r14', c_ulonglong),
        ('r13', c_ulonglong),
        ('r12', c_ulonglong),
        ('rbp', c_ulonglong),
        ('rbx', c_ulonglong),
        ('r11', c_ulonglong),
        ('r10', c_ulonglong),
        ('r9', c_ulonglong),
        ('r8', c_ulonglong),
        ('rax', c_ulonglong),
        ('rcx', c_ulonglong),
        ('rdx', c_ulonglong),
        ('rsi', c_ulonglong),
        ('rdi', c_ulonglong),
        ('orig_rax', c_ulonglong),
        ('rip', c_ulonglong),
        ('cs', c_ulonglong),
        ('eflags', c_ulonglong), # Name is eflags for historical reasons, often printed as rflags
        ('rsp', c_ulonglong),
        ('ss', c_ulonglong),
        ('fs_base', c_ulonglong),
        ('gs_base', c_ulonglong),
        ('ds', c_ulonglong),
        ('es', c_ulonglong),
        ('fs', c_ulonglong),
        ('gs', c_ulonglong),
    ]

# FXSAVE structure (used for PTRACE_GETREGSET with NT_PRFPREG on x64)
# Size is 512 bytes, alignment 16
class user_fpregs_struct_x64(Structure):
    _pack_ = 16
    _fields_ = [
        ('cwd', c_uint16),
        ('swd', c_uint16),
        ('ftw', c_uint16), # Different name (ftw vs twd) than x86 fpregs_struct
        ('fop', c_uint16),
        ('rip', c_uint64), # FPU instruction pointer
        ('rdp', c_uint64), # FPU operand pointer
        ('mxcsr', c_uint32),
        ('mxcsr_mask', c_uint32),
        ('st_space', c_uint8 * 128),  # 8 * 16 bytes
        ('xmm_space', c_uint8 * 256), # 16 * 16 bytes (XMM0-XMM15)
        # Padding to 512 bytes
        # Total size used: 2*4 (shorts) + 8*2 (longlongs) + 4*2 (ints) + 128 + 256 = 8 + 16 + 8 + 128 + 256 = 416
        # Padding needed: 512 - 416 = 96
        ('padding', c_uint8 * 96),
    ]
# print("Size of user_fpregs_struct_x64:", sizeof(user_fpregs_struct_x64)) # Check size

# --- Common ---
class IOVec(Structure):
    _fields_ = [
        ("iov_base", c_void_p),  # Pointer to the data buffer
        ("iov_len", c_size_t),   # Length of the data buffer
    ]

# Union/Classes to hold process state
# We need separate classes because the fields differ significantly
class ProcInfoX86:
    def __init__(self):
        self.pid = c_long(0)
        self.regs_struct = user_regs_struct_x86()
        self.old_regs_struct = user_regs_struct_x86()
        self.regs = IOVec()

        self.fpregs_struct = user_fpregs_struct_x86() # Basic FP regs (FSAVE/FNSAVE)
        self.old_fpregs_struct = user_fpregs_struct_x86()
        self.fpregs = IOVec()

        self.fpxregs_struct = user_fpxregs_struct_x86() # Extended FP/MMX/SSE (FXSAVE/FXRSTOR)
        self.old_fpxregs_struct = user_fpxregs_struct_x86()
        self.fpxregs = IOVec()

        self.sig = c_int(-1)
        self.exit_code = c_int(-1)

class ProcInfoX64:
    def __init__(self):
        self.pid = c_long(0)
        self.regs_struct = user_regs_struct_x64()
        self.old_regs_struct = user_regs_struct_x64()
        self.regs = IOVec()

        # On x64, NT_PRFPREG typically uses the FXSAVE format directly
        self.fpregs_struct = user_fpregs_struct_x64()
        self.old_fpregs_struct = user_fpregs_struct_x64()
        self.fpregs = IOVec()

        # NT_PRXFPREG might be used for more advanced state (AVX etc.), if supported/needed
        # For basic SSE, fpregs (NT_PRFPREG) is usually sufficient on x64.
        # We'll omit fpxregs for x64 for simplicity unless specifically needed.

        self.sig = c_int(-1)
        self.exit_code = c_int(-1)

# Helper to create the correct info structure
def create_proc_info(arch):
    if arch == 'x86':
        return ProcInfoX86()
    elif arch == 'x64':
        return ProcInfoX64()
    else:
        raise ValueError(f"Unsupported architecture for ProcInfo: {arch}")

# endregion





# region ARCH REG_INFO UTILS
def reg_info_x86(info: ProcInfoX86):
    regs: user_regs_struct_x86 = info.regs_struct
    old_regs: user_regs_struct_x86 = info.old_regs_struct

    print("-" * 80) # Separator

    print_reg32("eax=", "eax", regs, old_regs, " ")
    print_reg32("ebx=", "ebx", regs, old_regs, " ")
    print_reg32("ecx=", "ecx", regs, old_regs, " ")
    print_reg32("edx=", "edx", regs, old_regs, " ")
    print_reg32("esi=", "esi", regs, old_regs, " ")
    print_reg32("edi=", "edi", regs, old_regs, "\n")

    print_reg32("eip=", "eip", regs, old_regs, " ")
    print_reg32("esp=", "esp", regs, old_regs, " ")
    print_reg32("ebp=", "ebp", regs, old_regs, " ")

    # EFLAGS bits (using standard bit positions)
    eflags_val = regs.eflags
    old_eflags_val = old_regs.eflags

    cf = (eflags_val & 0x001) >> 0
    old_cf = (old_eflags_val & 0x001) >> 0
    pf = (eflags_val & 0x004) >> 2
    old_pf = (old_eflags_val & 0x004) >> 2
    af = (eflags_val & 0x010) >> 4
    old_af = (old_eflags_val & 0x010) >> 4
    zf = (eflags_val & 0x040) >> 6
    old_zf = (old_eflags_val & 0x040) >> 6
    sf = (eflags_val & 0x080) >> 7
    old_sf = (old_eflags_val & 0x080) >> 7
    df = (eflags_val & 0x400) >> 10
    old_df = (old_eflags_val & 0x400) >> 10
    of = (eflags_val & 0x800) >> 11
    old_of = (old_eflags_val & 0x800) >> 11

    print("Flags=[", end="")
    print_bit("CF:", cf, old_cf, " ")
    print_bit("PF:", pf, old_pf, " ")
    print_bit("AF:", af, old_af, " ")
    print_bit("ZF:", zf, old_zf, " ")
    print_bit("SF:", sf, old_sf, " ")
    print_bit("DF:", df, old_df, " ")
    print_bit("OF:", of, old_of, "] ")

    print_reg32("eflags=", "eflags", regs, old_regs, "\n")

    # Segment registers (usually 16-bit values, but stored in long/32-bit fields)
    print_reg16("cs=", "xcs", regs, old_regs, " ")
    print_reg16("ss=", "xss", regs, old_regs, " ")
    print_reg16("ds=", "xds", regs, old_regs, " ")
    print_reg16("es=", "xes", regs, old_regs, " ")
    print_reg16("fs=", "xfs", regs, old_regs, " ")
    print_reg16("gs=", "xgs", regs, old_regs, "\n")

    if settings.get('all_regs') == True:
        fpregs: user_fpregs_struct_x86 = info.fpregs_struct
        old_fpregs: user_fpregs_struct_x86 = info.old_fpregs_struct
        fpxregs: user_fpxregs_struct_x86 = info.fpxregs_struct
        old_fpxregs: user_fpxregs_struct_x86 = info.old_fpxregs_struct

        # --- Basic FP Regs (FSAVE) ---
        # Check if fpregs were actually retrieved (iov_len might be 0 if not supported/failed)
        if info.fpregs.iov_len >= sizeof(user_fpregs_struct_x86):
            print("\n--- FPU Registers (FSAVE state) ---")
            print_reg32("cwd=", "cwd", fpregs, old_fpregs, " ") # Control Word
            print_reg32("swd=", "swd", fpregs, old_fpregs, " ") # Status Word
            print_reg32("twd=", "twd", fpregs, old_fpregs, " ") # Tag Word
            print_reg32("fip=", "fip", fpregs, old_fpregs, "\n") # FPU IP Offset
            print_reg32("fcs=", "fcs", fpregs, old_fpregs, " ") # FPU IP Selector
            print_reg32("foo=", "foo", fpregs, old_fpregs, " ") # FPU Operand Offset
            print_reg32("fos=", "fos", fpregs, old_fpregs, "\n") # FPU Operand Selector

            print("ST Registers (80-bit, stored as 10 bytes each):")
            # st_space holds 8 ST registers, 10 bytes each = 80 bytes = 20 longs
            # Displaying them meaningfully requires parsing the 10-byte format.
            # For simplicity, just dump the raw longs for now.
            for i in range(8): # Display 2 longs per ST register (approx)
                st_idx_base = i * (10 // sizeof(c_long)) # Approx index in long array
                print(f" ST{i}: ", end="")
                # Need careful indexing and formatting for 10-byte values
                # This dump is just a placeholder showing raw data diffs
                for j in range(10 // sizeof(c_long)): # Typically 2 or 3 longs
                     idx = st_idx_base + j
                     if idx < len(fpregs.st_space):
                         dump_reg32_arr("st_space", idx, fpregs, old_fpregs)
                         print(" ", end="")
                print() # Newline per ST register
        else:
            print("\n--- FPU Registers (FSAVE state): Not Available ---")


        # --- Extended FP/MMX/SSE Regs (FXSAVE) ---
        if info.fpxregs.iov_len >= sizeof(user_fpxregs_struct_x86):
            print("\n--- Extended FPU/MMX/SSE Registers (FXSAVE state) ---")
            # Print FXSAVE specific fields
            print_reg16("cwd=", "cwd", fpxregs, old_fpxregs, " ")
            print_reg16("swd=", "swd", fpxregs, old_fpxregs, " ")
            print_reg16("twd=", "twd", fpxregs, old_fpxregs, " ") # Tag word
            print_reg16("fop=", "fop", fpxregs, old_fpxregs, "\n") # Last opcode
            # IP/Operand pointers - careful with 32/64 bit union possibilities
            print_reg32("fip=", "fip", fpxregs, old_fpxregs, " ")
            print_reg32("fcs=", "fcs", fpxregs, old_fpxregs, " ") # Check size/type
            print_reg32("foo=", "foo", fpxregs, old_fpxregs, " ")
            print_reg32("fos=", "fos", fpxregs, old_fpxregs, "\n") # Check size/type
            print_reg32("mxcsr=", "mxcsr", fpxregs, old_fpxregs, " ")
            print_reg32("mxcsr_mask=", "mxcsr_mask", fpxregs, old_fpxregs, "\n")

            print("ST/MMX Registers (fxsave layout):")
            # st_space in fxsave is 128 bytes (8 regs * 16 bytes each)
            st_fx_bytes = cast(fpxregs.st_space, POINTER(c_uint8 * 128)).contents
            old_st_fx_bytes = cast(old_fpxregs.st_space, POINTER(c_uint8 * 128)).contents
            for i in range(8):
                print(f" ST{i}/MM{i}: ", end="")
                for j in range(16): # 16 bytes per register
                    idx = i * 16 + j
                    # Simple byte comparison and printing
                    if st_fx_bytes[idx] == old_st_fx_bytes[idx]:
                         print(f"{st_fx_bytes[idx]:02x}", end="")
                    else:
                         print(f"{RED}{st_fx_bytes[idx]:02x}{RST}", end="")
                    if j % 4 == 3: print(" ", end="") # Add space every 4 bytes
                print()

            print("XMM Registers (0-7):")
            # xmm_space is 128 bytes (8 regs * 16 bytes each)
            xmm_bytes = cast(fpxregs.xmm_space, POINTER(c_uint8 * 128)).contents
            old_xmm_bytes = cast(old_fpxregs.xmm_space, POINTER(c_uint8 * 128)).contents
            for i in range(8): # XMM0-XMM7
                print(f" XMM{i}: ", end="")
                for j in range(16):
                    idx = i * 16 + j
                    if xmm_bytes[idx] == old_xmm_bytes[idx]:
                         print(f"{xmm_bytes[idx]:02x}", end="")
                    else:
                         print(f"{RED}{xmm_bytes[idx]:02x}{RST}", end="")
                    if j == 7: print(" ", end="") # Space in the middle
                print()
        else:
            print("\n--- Extended FPU/MMX/SSE Registers (FXSAVE state): Not Available ---")

    if info.sig.value != 5 and info.sig.value != -1: # Exclude SIGTRAP, show others
        logging.warning(f"[!] Process stopped by signal: {info.sig.value} ({signal.Signals(info.sig.value).name})")
    if info.exit_code.value != -1:
        logging.info(f"[+] Process exited with code: {info.exit_code.value}")

    print("-" * 80) # Footer separator


def reg_info_x64(info: ProcInfoX64):
    regs: user_regs_struct_x64 = info.regs_struct
    old_regs: user_regs_struct_x64 = info.old_regs_struct

    print("-" * 80)

    print_reg64("rax=", "rax", regs, old_regs, " ")
    print_reg64("rbx=", "rbx", regs, old_regs, " ")
    print_reg64("rcx=", "rcx", regs, old_regs, "\n")

    print_reg64("rdx=", "rdx", regs, old_regs, " ")
    print_reg64("rsi=", "rsi", regs, old_regs, " ")
    print_reg64("rdi=", "rdi", regs, old_regs, "\n")

    print_reg64("rip=", "rip", regs, old_regs, " ")
    print_reg64("rsp=", "rsp", regs, old_regs, " ")
    print_reg64("rbp=", "rbp", regs, old_regs, "\n")

    print_reg64(" r8=", "r8", regs, old_regs, " ")
    print_reg64(" r9=", "r9", regs, old_regs, " ")
    print_reg64("r10=", "r10", regs, old_regs, "\n")

    print_reg64("r11=", "r11", regs, old_regs, " ")
    print_reg64("r12=", "r12", regs, old_regs, " ")
    print_reg64("r13=", "r13", regs, old_regs, "\n")

    print_reg64("r14=", "r14", regs, old_regs, " ")
    print_reg64("r15=", "r15", regs, old_regs, " ")

    # RFLAGS bits
    rflags_val = regs.eflags # Field name is eflags in struct
    old_rflags_val = old_regs.eflags

    cf = (rflags_val & 0x001) >> 0
    old_cf = (old_rflags_val & 0x001) >> 0
    pf = (rflags_val & 0x004) >> 2
    old_pf = (old_rflags_val & 0x004) >> 2
    af = (rflags_val & 0x010) >> 4
    old_af = (old_rflags_val & 0x010) >> 4
    zf = (rflags_val & 0x040) >> 6
    old_zf = (old_rflags_val & 0x040) >> 6
    sf = (rflags_val & 0x080) >> 7
    old_sf = (old_rflags_val & 0x080) >> 7
    df = (rflags_val & 0x400) >> 10
    old_df = (old_rflags_val & 0x400) >> 10
    of = (rflags_val & 0x800) >> 11
    old_of = (old_rflags_val & 0x800) >> 11

    print("Flags=[", end="")
    print_bit("CF:", cf, old_cf, " ")
    print_bit("PF:", pf, old_pf, " ")
    print_bit("AF:", af, old_af, " ")
    print_bit("ZF:", zf, old_zf, " ")
    print_bit("SF:", sf, old_sf, " ")
    print_bit("DF:", df, old_df, " ")
    print_bit("OF:", of, old_of, "] ")

    print_reg64("rflags=", "eflags", regs, old_regs, "\n") # Print full rflags value

    # Segment registers (usually 16-bit selectors, but stored in 64-bit fields)
    # Base addresses are separate (fs_base, gs_base)
    print_reg16("cs=", "cs", regs, old_regs, " ")
    print_reg16("ss=", "ss", regs, old_regs, " ")
    print_reg16("ds=", "ds", regs, old_regs, " ") # DS/ES often unused/zero in 64-bit mode
    print_reg16("es=", "es", regs, old_regs, " ")
    print_reg16("fs=", "fs", regs, old_regs, " ")
    print_reg16("gs=", "gs", regs, old_regs, "\n")
    print_reg64("fs_base=", "fs_base", regs, old_regs, " ")
    print_reg64("gs_base=", "gs_base", regs, old_regs, "\n")


    if settings.get('all_regs') == True:
        # On x64, fpregs usually holds the FXSAVE state retrieved via NT_PRFPREG
        fpregs: user_fpregs_struct_x64 = info.fpregs_struct
        old_fpregs: user_fpregs_struct_x64 = info.old_fpregs_struct

        if info.fpregs.iov_len >= sizeof(user_fpregs_struct_x64):
            print("\n--- FPU/MMX/SSE Registers (FXSAVE state) ---")
            print_reg16("cwd=", "cwd", fpregs, old_fpregs, " ")
            print_reg16("swd=", "swd", fpregs, old_fpregs, " ")
            print_reg16("ftw=", "ftw", fpregs, old_fpregs, " ") # Tag word (abbreviated)
            print_reg16("fop=", "fop", fpregs, old_fpregs, "\n") # Last opcode
            print_reg64("rip=", "rip", fpregs, old_fpregs, " ") # FPU IP
            print_reg64("rdp=", "rdp", fpregs, old_fpregs, "\n") # FPU Operand Pointer
            print_reg32("mxcsr=", "mxcsr", fpregs, old_fpregs, " ")
            print_reg32("mxcsr_mask=", "mxcsr_mask", fpregs, old_fpregs, "\n")

            print("ST/MMX Registers (fxsave layout):")
            st_fx_bytes = cast(fpregs.st_space, POINTER(c_uint8 * 128)).contents
            old_st_fx_bytes = cast(old_fpregs.st_space, POINTER(c_uint8 * 128)).contents
            for i in range(8):
                print(f" ST{i}/MM{i}: ", end="")
                for j in range(16):
                    idx = i * 16 + j
                    if st_fx_bytes[idx] == old_st_fx_bytes[idx]:
                         print(f"{st_fx_bytes[idx]:02x}", end="")
                    else:
                         print(f"{RED}{st_fx_bytes[idx]:02x}{RST}", end="")
                    if j % 4 == 3: print(" ", end="")
                print()

            print("XMM Registers (0-15):")
            xmm_bytes = cast(fpregs.xmm_space, POINTER(c_uint8 * 256)).contents
            old_xmm_bytes = cast(old_fpregs.xmm_space, POINTER(c_uint8 * 256)).contents
            for i in range(16): # XMM0-XMM15
                print(f" XMM{i:<3}: ", end="") # Left align index for neatness
                for j in range(16):
                    idx = i * 16 + j
                    if xmm_bytes[idx] == old_xmm_bytes[idx]:
                         print(f"{xmm_bytes[idx]:02x}", end="")
                    else:
                         print(f"{RED}{xmm_bytes[idx]:02x}{RST}", end="")
                    if j == 7: print(" ", end="") # Space in the middle
                print()
        else:
             print("\n--- FPU/MMX/SSE Registers (FXSAVE state): Not Available ---")

    if info.sig.value != 5 and info.sig.value != -1:
        logging.warning(f"[!] Process stopped by signal: {info.sig.value} ({signal.Signals(info.sig.value).name})")
    if info.exit_code.value != -1:
        logging.info(f"[+] Process exited with code: {info.exit_code.value}")

    print("-" * 80)
# endregion





# region RAPPEL KEYSTONE
class RappelKeystone:
    def __init__(self, arch):
        """Initializes Keystone for the specified architecture."""
        self.arch_name = arch # Store 'x86' or 'x64'
        self.ks = None
        self.ks_arch = None
        self.ks_mode = None

        if arch == 'x86':
            self.ks_arch = keystone.KS_ARCH_X86
            self.ks_mode = keystone.KS_MODE_32
        elif arch == 'x64':
            self.ks_arch = keystone.KS_ARCH_X86 # Use KS_ARCH_X86 for both
            self.ks_mode = keystone.KS_MODE_64
        else:
            raise ValueError(f"Keystone unsupported architecture: {arch}")

        try:
            self.ks = keystone.Ks(self.ks_arch, self.ks_mode)
        except keystone.KsError as e:
            logging.error(f"[-] Failed to initialize Keystone for {arch}: {e}")
            raise # Re-raise the exception

    def assemble(self, code: str, addr: int):
        """Assembles the code string at the given virtual address."""
        if not self.ks:
            raise RuntimeError("Keystone assembler not initialized.")
        try:
            # addr should be an integer representing the virtual address
            bytecode, count = self.ks.asm(code, addr, as_bytes=True)
            logging.info(f"[*] Assembled {count} instructions at 0x{addr:x}: {bytecode.hex()}") # Debug
            return bytecode, count
        except keystone.KsError as e:
            # Provide more context in the error message
            logging.error(f"[-] Keystone Error: {e}")
            logging.error(f"    Architecture: {self.arch_name}, Mode: {self.ks_mode}")
            logging.error(f"    Address: 0x{addr:x}")
            logging.error(f"    Code: '{code.strip()}'")
            return None, 0 # Return None or empty bytes on error

# endregion





# region RAPPEL PTRACE

# --- Load libc ---
# Find libc path
libc_path = ctypes.util.find_library('c')
if not libc_path:
    raise ImportError("Could not find libc library.")

try:
    # Load libc using cdll
    libc = cdll.LoadLibrary(libc_path)
except OSError as e:
    logging.error(f"[-] Failed to load libc from {libc_path}: {e}")
    # Try loading a specific wrapper if direct libc fails or is insufficient
    # Example: libc = cdll.LoadLibrary("./libs/clib_wrapper_64.so")
    # Make sure the wrapper exists and is compatible.
    # For standard ptrace, direct libc should usually work.
    sys.exit(1)

# --- Define ptrace function prototype ---
# int ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
try:
    libc.ptrace.argtypes = [c_int, c_int, c_void_p, c_void_p]
    libc.ptrace.restype = c_long # ptrace returns a long

    # Define waitpid if needed (though os.waitpid is usually sufficient)
    libc.waitpid.argtypes = [c_int, POINTER(c_int), c_int]
    libc.waitpid.restype = c_int

    # Define fexecve if needed (os.execve might work with path, fexecve needs fd)
    # int fexecve(int fd, char *const argv[], char *const envp[]);
    # Need to handle C arrays of strings (char *const [])
    # This is complex with ctypes, often easier to use os.execvpe or similar
    # If fexecve is strictly required, more setup is needed.
    # For now, let's assume os.execve or similar can be used via path later.
    # If using the provided fexecve wrapper:
    # libc.fexecve.argtypes = [c_int, POINTER(c_char_p), POINTER(c_char_p)]
    # libc.fexecve.restype = c_int

except AttributeError as e:
     logging.error(f"[-] Error setting up ctypes for libc functions: {e}")
     print("    Ensure libc was loaded correctly and exports ptrace, waitpid.")
     sys.exit(1)


# ptrace(2) constants from sys/ptrace.h (subset)
PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1   # Read word at location addr in tracee's memory
PTRACE_PEEKDATA = 2   # Read word at location addr in tracee's memory
PTRACE_POKETEXT = 4   # Write word data at location addr in tracee's memory
PTRACE_POKEDATA = 5   # Write word data at location addr in tracee's memory
PTRACE_CONT = 7       # Continue execution
PTRACE_SINGLESTEP = 9 # Execute one instruction
PTRACE_GETREGS = 12   # Get GP registers (struct user_regs_struct) - Use GETREGSET instead
PTRACE_SETREGS = 13   # Set GP registers - Use SETREGSET instead
PTRACE_GETFPREGS = 14 # Get FP registers (struct user_fpregs_struct) - Use GETREGSET instead
PTRACE_SETFPREGS = 15 # Set FP registers - Use SETREGSET instead
PTRACE_ATTACH = 16    # Attach to a running process
PTRACE_DETACH = 17    # Detach from a process
PTRACE_GETFPXREGS = 18 # Get FP/SSE registers (struct user_fpxregs_struct) - Use GETREGSET instead
PTRACE_SETFPXREGS = 19 # Set FP/SSE registers - Use SETREGSET instead
PTRACE_SYSCALL = 24   # Continue and stop at next syscall entry/exit

PTRACE_KILL = 31      # Kill the process (not in sys/ptrace.h, but useful)

PTRACE_SETOPTIONS = 0x4200
PTRACE_GETEVENTMSG = 0x4201
PTRACE_GETSIGINFO = 0x4202
PTRACE_SETSIGINFO = 0x4203
PTRACE_GETREGSET = 0x4204
PTRACE_SETREGSET = 0x4205

# PTRACE_SETOPTIONS options
PTRACE_O_TRACESYSGOOD = 1
PTRACE_O_TRACEFORK = (1 << 1)
PTRACE_O_TRACEVFORK = (1 << 2)
PTRACE_O_TRACECLONE = (1 << 3)
PTRACE_O_TRACEEXEC = (1 << 4)
PTRACE_O_TRACEVFORKDONE = (1 << 5)
PTRACE_O_TRACEEXIT = (1 << 6)
PTRACE_O_EXITKILL = (1 << 20)

# Ptrace event numbers (for status>>8)
PTRACE_EVENT_FORK = 1
PTRACE_EVENT_VFORK = 2
PTRACE_EVENT_CLONE = 3
PTRACE_EVENT_EXEC = 4
PTRACE_EVENT_VFORK_DONE = 5
PTRACE_EVENT_EXIT = 6           # <<<--- ADD THIS LINE
PTRACE_EVENT_SECCOMP = 7
PTRACE_EVENT_STOP = 128

# GETREGSET/SETREGSET constants (address argument)
# These might vary slightly; check <linux/elf.h> or <sys/procfs.h>
NT_PRSTATUS = 1      # General purpose registers (user_regs_struct)
NT_PRFPREG = 2       # Floating point registers (user_fpregs_struct or fxsave format)
NT_PRPSINFO = 3      # Process state info (prpsinfo_t)
NT_TASKSTRUCT = 4    # Task struct info
NT_AUXV = 6          # Auxiliary vector
# Specific to x86/x64 for extended state:
NT_X86_XSTATE = 0x202 # AVX, etc. via xsave format

# NT_PRXFPREG seems less standard than using NT_PRFPREG (for fxsave on x64)
# or NT_X86_XSTATE (for xsave). Let's prefer NT_PRFPREG.
# If FXSAVE is needed explicitly on 32-bit, NT_PRFPREG might give FSAVE,
# and a different constant or GETFPXREGS might be needed.
# Let's stick to GETREGSET with NT_PRSTATUS and NT_PRFPREG for broader compatibility.

# Word size for PEEK/POKE depends on architecture
WORD_SIZE = 8 if settings['arch'] == 'x64' else 4
PACK_FMT = 'Q' if settings['arch'] == 'x64' else 'I'
PACK_SIZE = 8 if settings['arch'] == 'x64' else 4


class Ptrace:
    def __init__(self, arch):
        self.arch = arch
        # Use host long size for ptrace word operations (compat tracee on 64-bit host still uses 8-byte words)
        host_long_bytes = ctypes.sizeof(c_long)
        self.word_size = host_long_bytes
        if host_long_bytes == 8:
            self.word_mask = 0xffffffffffffffff
            self.pack_fmt = '<Q'
        else:
            self.word_mask = 0xffffffff
            self.pack_fmt = '<I'

    def _ptrace_call(self, request, pid, addr, data):
        """Wrapper for libc.ptrace with improved type handling for 'data'."""
        ctypes.set_errno(0)

        # addr is usually an address (int) or a request-specific int (like NT_PRSTATUS)
        # Keep casting addr to c_void_p if it's an int, as ptrace expects void* addr
        addr_arg = c_void_p(addr) if isinstance(addr, int) else addr

        # --- Refined data_arg handling ---
        data_arg = None
        if request in (PTRACE_POKEDATA, PTRACE_POKETEXT):
            # For POKE, 'data' is the integer value to write.
            # Pass the integer directly; ctypes handles marshalling to pointer-sized data.
            data_arg = data
        elif request in (PTRACE_GETREGSET, PTRACE_SETREGSET,
                         PTRACE_GETSIGINFO, PTRACE_SETSIGINFO,
                         PTRACE_GETEVENTMSG):
            # For these, 'data' is expected to be a pointer (e.g., byref(struct)).
            # Pass the pointer type (like LP_IOVec from byref) directly.
            data_arg = data
        elif request in (PTRACE_PEEKDATA, PTRACE_PEEKTEXT):
             # For PEEK, 'data' is typically ignored/NULL (0).
             # Pass 0 cast to c_void_p.
             data_arg = c_void_p(data) # data should be 0 or None here
        elif request in (PTRACE_CONT, PTRACE_SYSCALL, PTRACE_DETACH,
                         PTRACE_SINGLESTEP, PTRACE_KILL):
            # For CONT/SYSCALL/etc., 'data' is the signal number (integer).
            # Pass the integer directly.
             data_arg = data
        elif request == PTRACE_SETOPTIONS:
             # For SETOPTIONS, 'data' contains the option flags (integer).
             # Pass the integer directly.
             data_arg = data
        elif request == PTRACE_TRACEME:
             # TRACEME ignores addr and data. Pass 0 for both as c_void_p.
             addr_arg = c_void_p(0)
             data_arg = c_void_p(0)
        else:
            # Default for unknown requests: Assume data might be a pointer or 0/None.
            # Try casting to c_void_p, but log a warning.
            print(f"[!] Warning: Unhandled ptrace request type {request} in _ptrace_call data handling.")
            # Check if data is already a ctypes pointer type before casting
            if isinstance(data, ctypes._Pointer):
                 data_arg = data
            else:
                 data_arg = c_void_p(data) # Cast integers/None

        # --- End Refined data_arg handling ---


        # Debugging print (optional)
        # print(f"[Debug] ptrace({request}, {pid}, addr={addr_arg}, data={data_arg})",
        #       f"(orig addr: {addr}, orig data: {data}, type(data_arg): {type(data_arg)})")


        result = libc.ptrace(request, pid, addr_arg, data_arg)
        err = ctypes.get_errno()

        # --- Error Checking ---
        # PEEK requests return data; -1 is ambiguous
        if request in (PTRACE_PEEKTEXT, PTRACE_PEEKDATA):
            if result == -1 and err != 0:
                 raise OSError(err, f"ptrace({request}, pid={pid}, addr={addr:#x}) failed: {os.strerror(err)}")
            return result # Return the data (potentially signed -1)
        # Other requests return 0 on success, -1 on error
        elif result == -1:
             # Check for expected ESRCH when process might already be gone
             if err == errno.ESRCH and request in (PTRACE_CONT, PTRACE_DETACH, PTRACE_KILL,
                                                  PTRACE_GETREGSET, PTRACE_SETREGSET, # Also check for GET/SET
                                                  PTRACE_GETSIGINFO, PTRACE_SETSIGINFO,
                                                  PTRACE_GETEVENTMSG):
                 # Don't print error for common cases where process might die between steps
                 # print(f"[*] Note: ptrace({request}, pid={pid}) failed: Process already exited (ESRCH).")
                 return result # Allow caller (like _try_collect_regs) to handle
             # Raise error for other failures
             raise OSError(err, f"ptrace({request}, pid={pid}, addr={addr}, data={data}) failed: {os.strerror(err)}")

        return result # Return 0 on success for non-PEEK requests

    def child(self, exe_fd, exe_path):
        """Prepare child process for tracing and execute the target."""
        try:
            # Allow parent to trace this process
            self._ptrace_call(PTRACE_TRACEME, 0, None, None)

            # Execute the target program using os.execve
            # os.execve requires the path and Python list/tuple for args/env

            # Argument list for the program (at least the program name itself)
            # Must be bytes or strings. Using bytes is safer.
            program_name = os.path.basename(exe_path).encode('utf-8') # Get filename part
            py_argv = [program_name] # Python list containing bytes

            # Environment variables (inherit from parent)
            py_env = os.environ

            # Replace the current process image
            # print(f"[Child Debug] Calling execve: path='{exe_path}', argv={py_argv}, env=...") # Debug
            os.execve(exe_path, py_argv, py_env)

            # If execve returns, an error occurred
            err = ctypes.get_errno()
            logging.error(f"[-] Child: execve failed for '{exe_path}': {os.strerror(err)}")
            os._exit(1) # Use _exit in child after fork

        except Exception as e:
            # Catch potential exceptions during setup or execve call itself
            logging.error(f"[-] Child process error during PTRACE_TRACEME or execve preparation: {e}")
            os._exit(1) # Ensure child exits on any error here

    def launch(self, pid):
        """Wait for initial SIGTRAP from child and set options."""
        try:
            # Wait for the SIGTRAP after execve
            status = c_int(0)
            ret = libc.waitpid(pid, byref(status), 0)
            if ret < 0:
                err = ctypes.get_errno()
                raise OSError(err, f"waitpid failed for initial trap (pid={pid}): {os.strerror(err)}")

            if not os.WIFSTOPPED(status.value) or os.WSTOPSIG(status.value) != signal.SIGTRAP:
                 print(f"[!] Expected SIGTRAP after execve, but got status {status.value:#x}")
                 # Optionally decode status here (WIFEXITED, WIFSIGNALED etc.)
                 return False # Indicate failure

            logging.info(f"[*] Child process (pid={pid}) stopped with SIGTRAP (initial).")

            # Set options, e.g., to trace exit events
            options = PTRACE_O_TRACEEXIT
            self._ptrace_call(PTRACE_SETOPTIONS, pid, None, options)
            logging.info(f"[*] Set PTRACE_O_TRACEEXIT option for pid={pid}.")
            return True # Indicate success

        except OSError as e:
            logging.error(f"[-] Error launching/waiting for process {pid}: {e}")
            return False
        except Exception as e:
            logging.error(f"[-] Unexpected error during launch: {e}")
            return False

    def cont(self, pid):
        """Continue the execution of the process."""
        try:
            # No signal is sent (signal 0)
            self._ptrace_call(PTRACE_CONT, pid, None, 0)
            # print(f"[*] Continued process {pid}") # Debug
        except OSError as e:
            # Ignore ESRCH if process died between reap and cont
            if e.errno != errno.ESRCH:
                 logging.error(f"[-] Error continuing process {pid}: {e}")
                 raise # Re-raise unexpected errors

    def detach(self, pid):
        """Detach from the process, letting it run freely."""
        try:
            self._ptrace_call(PTRACE_DETACH, pid, None, 0)
            logging.info(f"[*] Detached from process {pid}")
        except OSError as e:
            if e.errno != errno.ESRCH:
                logging.error(f"[-] Error detaching from process {pid}: {e}")
                # Decide whether to raise or just warn

    def reap(self, pid, info):
        """Wait for the process to stop or exit, collect status and registers."""
        try:
            status = c_int(0)
            # WNOHANG could be used for non-blocking check, but we want to wait
            ret = libc.waitpid(pid, byref(status), 0) # Blocking wait

            if ret < 0:
                err = ctypes.get_errno()
                # If waitpid fails with ECHILD, the process is already gone (e.g. detached and exited)
                if err == errno.ECHILD:
                    logging.info(f"[*] waitpid({pid}): No such child process (already reaped or detached?). Assuming exited.")
                    info.sig.value = 0 # Treat as normal exit if we lost track
                    info.exit_code.value = 0
                    return 1 # Indicate exit
                raise OSError(err, f"waitpid failed for pid={pid}: {os.strerror(err)}")

            info.sig.value = -1 # Reset signal/exit info
            info.exit_code.value = -1

            if os.WIFEXITED(status.value):
                exit_code = os.WEXITSTATUS(status.value)
                logging.info(f"[+] Process {pid} exited normally with code {exit_code}.")
                info.exit_code.value = exit_code
                info.sig.value = 0 # Indicate normal exit
                # Optionally collect final regs before returning? Ptrace might fail here.
                # self._try_collect_regs(pid, info)
                return 1 # Indicate process finished

            if os.WIFSIGNALED(status.value):
                term_sig = os.WTERMSIG(status.value)
                try:
                    sig_name = signal.Signals(term_sig).name
                except ValueError:
                    sig_name = "Unknown"
                logging.error(f"[-] Process {pid} terminated by signal {term_sig} ({sig_name}).")
                info.sig.value = term_sig
                # self._try_collect_regs(pid, info)
                return 1 # Indicate process finished

            if os.WIFSTOPPED(status.value):
                stop_sig = os.WSTOPSIG(status.value)

                # Check for ptrace events (like PTRACE_EVENT_EXIT)
                # These are signaled by SIGTRAP | (event << 8)
                if stop_sig == signal.SIGTRAP and (status.value >> 8) > 0:
                    event = status.value >> 16 # Event is in the high bits
                    if event == PTRACE_EVENT_EXIT:
                        logging.info(f"[*] Process {pid} stopped with PTRACE_EVENT_EXIT.")
                        # Get exit code using GETEVENTMSG
                        exit_code_ptr = pointer(c_ulong(0))
                        try:
                            self._ptrace_call(PTRACE_GETEVENTMSG, pid, None, exit_code_ptr)
                            info.exit_code.value = exit_code_ptr.contents.value
                            logging.info(f"[+] Exit code reported: {info.exit_code.value}")
                        except OSError as e:
                            logging.error(f"[-] Failed to get exit code via PTRACE_GETEVENTMSG: {e}")
                            info.exit_code.value = -1 # Mark as unknown

                        # Collect final registers before confirming exit
                        self._collect_regs(pid, info)
                        info.sig.value = 0 # Treat as exited for display purposes
                        return 1 # Indicate process finished (at exit trap)
                    else:
                        # Handle other events if needed (FORK, CLONE, EXEC, etc.)
                        logging.info(f"[*] Process {pid} stopped with SIGTRAP and event {event:#x}.")
                        # Treat as a regular stop for now
                        self._collect_regs(pid, info)
                        info.sig.value = stop_sig # Report the SIGTRAP
                        return 0 # Indicate stopped, ready for next instruction

                # Regular signal stop (including SIGTRAP from INT3)
                try:
                    sig_name = signal.Signals(stop_sig).name
                except ValueError:
                    sig_name = "Unknown"

                if stop_sig == signal.SIGTRAP:
                     # Likely hit our INT3 breakpoint
                     # print(f"[*] Process {pid} stopped with SIGTRAP (breakpoint).") # Less verbose
                     pass
                else:
                    logging.info(f"[*] Process {pid} stopped by signal {stop_sig} ({sig_name}).")

                # Collect registers on any stop
                self._collect_regs(pid, info)
                info.sig.value = stop_sig
                return 0 # Indicate stopped, ready for next instruction

            # Should not happen if waitpid returned successfully
            print(f"[!] Unknown wait status for pid={pid}: {status.value:#x}")
            return 1 # Treat as finished to avoid infinite loop

        except OSError as e:
            # If reap fails with ESRCH, the process is already gone
            if e.errno == errno.ESRCH:
                logging.info(f"[*] reap({pid}): Process already exited (ESRCH).")
                info.sig.value = 0
                info.exit_code.value = 0
                return 1 # Indicate exited
            logging.error(f"[-] Error reaping process {pid}: {e}")
            # Decide how to handle this - maybe treat as exited?
            return 1
        except Exception as e:
            logging.error(f"[-] Unexpected error during reap: {e}")
            return 1 # Treat as finished


    def read(self, pid, base_address, size):
        """Reads 'size' bytes from 'base_address' in the child process."""
        data = bytearray(size)
        addr = base_address
        bytes_read = 0

        try:
            while bytes_read < size:
                # Align address for PEEKDATA
                aligned_addr = addr & ~(self.word_size - 1)
                addr_offset = addr - aligned_addr

                # Read a word (result might be signed)
                word_val_signed = self._ptrace_call(PTRACE_PEEKDATA, pid, aligned_addr, None)

                # --- FIX: Treat the bits as unsigned using the mask ---
                word_val_unsigned = word_val_signed & self.word_mask

                # Pack the *unsigned* word value into bytes
                word_bytes = struct.pack(self.pack_fmt, word_val_unsigned)

                # Copy the relevant bytes from the read word into our buffer
                bytes_to_copy = min(self.word_size - addr_offset, size - bytes_read)
                data[bytes_read : bytes_read + bytes_to_copy] = \
                    word_bytes[addr_offset : addr_offset + bytes_to_copy]

                bytes_read += bytes_to_copy
                addr += bytes_to_copy

            return bytes(data)

        except OSError as e:
            logging.error(f"[-] Error reading memory from pid={pid} at {base_address:#x} (size={size}): {e}")
            return None

    def write(self, pid, base_address, data):
        """Writes the 'data' (bytes) to 'base_address' in the child process."""
        size = len(data)
        addr = base_address
        bytes_written = 0

        try:
            while bytes_written < size:
                # Align address for POKEDATA
                aligned_addr = addr & ~(self.word_size - 1)
                addr_offset = addr - aligned_addr

                # Determine how many bytes to write in this iteration
                bytes_to_write_this_word = min(self.word_size - addr_offset, size - bytes_written)

                # If the write doesn't span the whole word or isn't aligned, read original word
                if addr_offset != 0 or bytes_to_write_this_word != self.word_size:
                    original_word_val_signed = self._ptrace_call(PTRACE_PEEKDATA, pid, aligned_addr, None)
                    # --- FIX: Treat the bits as unsigned ---
                    original_word_val_unsigned = original_word_val_signed & self.word_mask
                    original_word_bytes = bytearray(struct.pack(self.pack_fmt, original_word_val_unsigned))
                else:
                    # Writing a full, aligned word, no need to read first
                    original_word_bytes = bytearray(self.word_size)

                # Overwrite the relevant part of the word_bytes with new data
                new_data_chunk = data[bytes_written : bytes_written + bytes_to_write_this_word]
                original_word_bytes[addr_offset : addr_offset + bytes_to_write_this_word] = new_data_chunk

                # Unpack the modified byte array back into an *unsigned* word value
                modified_word_val_unsigned = struct.unpack(self.pack_fmt, original_word_bytes)[0]

                # Write the modified word back using POKEDATA
                # --- FIX: Pass the integer value directly as the 'data' argument ---
                self._ptrace_call(PTRACE_POKEDATA, pid, aligned_addr, modified_word_val_unsigned)

                bytes_written += bytes_to_write_this_word
                addr += bytes_to_write_this_word

            return True

        except OSError as e:
            logging.error(f"[-] Error writing memory to pid={pid} at {base_address:#x} (size={size}): {e}")
            return False

    def init_proc_info(self, info):
        """Sets up the IOVec structures within the ProcInfo object."""
        # General Purpose Regs
        info.regs.iov_base = addressof(info.regs_struct)
        if self.arch == 'x86':
            info.regs.iov_len = sizeof(user_regs_struct_x86)
        else: # x64
            info.regs.iov_len = sizeof(user_regs_struct_x64)

        # Floating Point Regs (using appropriate structure based on arch)
        info.fpregs.iov_base = addressof(info.fpregs_struct)
        if self.arch == 'x86':
             # Use FSAVE struct for NT_PRFPREG on x86? Or should it be FXSAVE?
             # Let's assume FSAVE for NT_PRFPREG first.
            info.fpregs.iov_len = sizeof(user_fpregs_struct_x86)

            # Extended FP/SSE Regs (FXSAVE for x86)
            info.fpxregs.iov_base = addressof(info.fpxregs_struct)
            info.fpxregs.iov_len = sizeof(user_fpxregs_struct_x86)
        else: # x64
            # NT_PRFPREG on x64 typically uses FXSAVE format
            info.fpregs.iov_len = sizeof(user_fpregs_struct_x64)
            # No separate fpxregs defined for x64 in this setup

    def _try_collect_regs(self, pid, info):
        """Attempts to collect registers, ignoring errors (e.g., if process died)."""
        try:
            self._collect_regs(pid, info)
        except OSError as e:
            # Ignore ESRCH (process died) or EIO (ptrace error after exit)
            if e.errno in (errno.ESRCH, errno.EIO):
                # print(f"[*] Note: Could not collect final registers for pid={pid}: {e}")
                pass
            else:
                print(f"[!] Warning: Unexpected error collecting final registers for pid={pid}: {e}")

    def _collect_regs(self, pid, info):
        """Collects GPRs and FPRs using PTRACE_GETREGSET."""
        info.pid = pid

        # --- Get General Purpose Registers (NT_PRSTATUS) ---
        # Save current GPRs as old GPRs before getting new ones
        if self.arch == 'x86':
            info.old_regs_struct = user_regs_struct_x86.from_buffer_copy(info.regs_struct)
        else:
            info.old_regs_struct = user_regs_struct_x64.from_buffer_copy(info.regs_struct)

        try:
            self._ptrace_call(PTRACE_GETREGSET, pid, NT_PRSTATUS, byref(info.regs))
        except OSError as e:
            logging.error(f"[-] Failed to get GPRs (NT_PRSTATUS) for pid={pid}: {e}")
            # Optionally clear current regs or re-raise
            raise

        # --- Get Floating Point Registers (NT_PRFPREG) ---
         # Save current FPRs as old FPRs
        if self.arch == 'x86':
            # Check if FSAVE struct is non-zero before copying (might fail first time)
            if info.fpregs.iov_len >= sizeof(user_fpregs_struct_x86):
                 info.old_fpregs_struct = user_fpregs_struct_x86.from_buffer_copy(info.fpregs_struct)
        else: # x64
            if info.fpregs.iov_len >= sizeof(user_fpregs_struct_x64):
                 info.old_fpregs_struct = user_fpregs_struct_x64.from_buffer_copy(info.fpregs_struct)

        try:
            self._ptrace_call(PTRACE_GETREGSET, pid, NT_PRFPREG, byref(info.fpregs))
            # Check actual length returned in iov_len if needed, though it might not be updated by kernel
        except OSError as e:
            # This might fail if FP unit isn't enabled or GETREGSET doesn't support NT_PRFPREG well
            # print(f"[*] Note: Failed to get FPRs (NT_PRFPREG) for pid={pid}: {e}")
            # Mark fpregs as invalid/unavailable by setting iov_len to 0?
            info.fpregs.iov_len = 0

        # --- Get Extended Registers (NT_PRXFPREG for x86 FXSAVE) ---
        if self.arch == 'x86' and hasattr(info, 'fpxregs'):
            if info.fpxregs.iov_len >= sizeof(user_fpxregs_struct_x86):
                 info.old_fpxregs_struct = user_fpxregs_struct_x86.from_buffer_copy(info.fpxregs_struct)
            try:
                 # Constant for NT_PRXFPREG needs verification. Using standard name.
                 # May need PTRACE_GETFPXREGS if GETREGSET doesn't work.
                 # Define NT_PRXFPREG if not defined above:
                 if 'NT_PRXFPREG' not in globals():
                      NT_PRXFPREG = 0x46e62b7f # Value from original code, check system headers

                 # Ensure iov_len is set correctly before call
                 info.fpxregs.iov_len = sizeof(user_fpxregs_struct_x86)
                 self._ptrace_call(PTRACE_GETREGSET, pid, NT_PRXFPREG, byref(info.fpxregs))
            except OSError as e:
                 # print(f"[*] Note: Failed to get Extended FPRs (NT_PRXFPREG) for pid={pid}: {e}")
                 info.fpxregs.iov_len = 0

        # Reset signal/exit code unless they were set by reap() logic
        # This method is usually called *after* reap sets signal/exit status
        # So, we don't reset them here. Reap handles that.
# endregion





# region RAPPEL UI
class Rappel:
    def __init__(self, arch='x64'):
        self.arch = arch
        self.__in_block = False
        self.exe_file_obj: ExecutableFile | None = None # Store the wrapper object
        self.exe_fd = -1         # Store the integer fd separately if needed often
        self.exe_path = None       # Store the path
        self.ptrace = None
        self.keystone = None
        self.child_pid = -1
        self.proc_info = None
        self.current_addr = settings['start_addr']

        try:
            # 1. Initialize Keystone
            self.keystone = RappelKeystone(self.arch)

            # 2. Create initial buffer
            initial_code_buffer = create_string_buffer(PAGE_SIZE)
            memset(initial_code_buffer, TRAP, PAGE_SIZE)

            # 3. Generate the ELF executable
            logging.info("[*] Generating minimal ELF executable...")
            elf = ELF(self.arch, code=initial_code_buffer.raw, code_size=PAGE_SIZE)
            elf_size = elf.gen_elf()
            # print(f"[*] ELF generated ({elf_size} bytes).") # Less verbose

            # 4. Write ELF to a temporary executable file
            logging.info(f"[*] Writing executable to temporary file in '{settings['path']}'...")
            self.exe_file_obj = RappelExe.write(elf.out, path=None) # Store the returned object
            if self.exe_file_obj is None:
                 raise RuntimeError("Failed to write executable file.")

            self.exe_fd = self.exe_file_obj.fileno() # Get the integer fd
            self.exe_path = self.exe_file_obj.path  # Get the path
            logging.info(f"[*] Executable written to: {self.exe_path} (fd: {self.exe_fd})")


            # 5. Initialize Ptrace wrapper
            self.ptrace = Ptrace(self.arch)

            # 6. Create ProcInfo structure
            self.proc_info = create_proc_info(self.arch)
            self.ptrace.init_proc_info(self.proc_info)

        except Exception as e:
            logging.error(f"[-] Initialization failed: {e}")
            # Ensure cleanup happens even if init fails partially
            self.cleanup()
            # Re-raise or exit
            sys.exit(1)

    def __trace_child(self):
        """Forks and execs the child process under PTRACE_TRACEME."""
        try:
            pid = os.fork()
            if pid == 0:
                # --- Child Process ---
                # Close the read-only fd inherited from parent? Not strictly necessary.
                # os.close(self.exe_fd) # Child uses path for execve
                self.ptrace.child(self.exe_fd, self.exe_path) # Will call TRACEME and execve
                # child() only returns if execve fails
                os._exit(1) # Ensure child exits if exec fails

            elif pid > 0:
                # --- Parent Process ---
                logging.info(f"[+] Child process started (pid={pid}).")
                # Parent should close the write fd if it was kept open,
                # but RappelExe closes it before returning ro_fd.
                # The ro_fd (self.exe_fd) might be kept open for debugging/inspection,
                # but isn't strictly needed after execve.
                return pid
            else:
                # --- Fork Failed ---
                err = ctypes.get_errno()
                raise OSError(err, f"Failed to fork: {os.strerror(err)}")

        except Exception as e:
            logging.error(f"[-] Error forking/execing child: {e}")
            return -1 # Indicate failure

    def display_info(self):
        """Displays the current register state based on architecture."""
        if not self.proc_info: return
        try:
            if self.arch == 'x86':
                reg_info_x86(self.proc_info)
            elif self.arch == 'x64':
                reg_info_x64(self.proc_info)
            else:
                print(f"[!] Unknown architecture for display: {self.arch}")
        except Exception as e:
             print(f"[!] Error displaying register info: {e}")


    def interact(self):
        """Main interactive loop."""
        try:
            # 1. Launch the child process
            self.child_pid = self.__trace_child()
            if self.child_pid < 0:
                raise RuntimeError("Failed to start child process.")

            # 2. Wait for initial trap and set options
            if not self.ptrace.launch(self.child_pid):
                 raise RuntimeError("Failed initial ptrace setup with child.")

            # 3. Initial register collection and display
            # Need to continue once to let it hit the first INT3 at start_addr
            logging.info("[*] Continuing child to first instruction...")
            self.ptrace.cont(self.child_pid)
            if self.ptrace.reap(self.child_pid, self.proc_info) == 1:
                logging.error("[-] Child exited unexpectedly during initial run.")
                self.display_info() # Show final state
                return # Exit interaction

            logging.info("[*] Child stopped at entry point. Initial state:")
            self.display_info()

            # Set current address based on RIP/EIP after initial stop
            if self.arch == 'x64':
                self.current_addr = self.proc_info.regs_struct.rip
            else: # x86
                self.current_addr = self.proc_info.regs_struct.eip
            logging.info(f"[*] Current address: {self.current_addr:#x}")

            # --- Main Interaction Loop ---
            while True:
                try:
                    line = self.__prompt()
                    if not line or line.lower() in ['q', 'quit', 'exit']:
                        break
                    if line.lower() in ['r', 'regs']:
                        self.display_info()
                        continue
                    if line.lower() in ['h', 'help']:
                         print("Commands: <assembly>, regs (r), quit (q), help (h)")
                         continue

                    # Assemble the instruction
                    bytecode, count = self.keystone.assemble(line, self.current_addr)

                    if bytecode is None or count == 0:
                        # Assembly error already printed by Keystone wrapper
                        continue

                    instruction_size = len(bytecode)

                    # Write the instruction bytes to memory, overwriting TRAP(s)
                    if not self.ptrace.write(self.child_pid, self.current_addr, bytecode):
                        logging.error("[-] Failed to write instruction to memory. Aborting.")
                        break

                    # If using INT3 breakpoints, restore original byte after single step? No, we overwrite permanently.
                    # If using PTRACE_SINGLESTEP:
                    # self.ptrace.singlestep(self.child_pid)
                    # If using INT3 breakpoints (current setup):
                    # Continue execution; it will run the new instruction and hit the *next* INT3
                    self.ptrace.cont(self.child_pid)


                    # Wait for the process to stop (hit next INT3 or other signal) or exit
                    exit_status = self.ptrace.reap(self.child_pid, self.proc_info)

                    # Display the result
                    self.display_info()

                    if exit_status == 1:
                        logging.info("[*] Process finished.")
                        break # Exit loop if process terminated

                    # Update current address for next instruction based on EIP/RIP
                    if self.arch == 'x64':
                         # If it stopped at the *next* byte (intended INT3):
                         expected_next_addr = self.current_addr + instruction_size + 1
                         actual_next_addr = self.proc_info.regs_struct.rip
                         if actual_next_addr != expected_next_addr:
                              logging.warning(f"[!] Warning: RIP is {actual_next_addr:#x}, expected {expected_next_addr:#x}. Control flow changed?")
                         self.current_addr = actual_next_addr
                    else: # x86
                         # Account for INT3 size (1 byte) at the next location
                         expected_next_addr = self.current_addr + instruction_size + 1
                         actual_next_addr = self.proc_info.regs_struct.eip
                         if actual_next_addr != expected_next_addr:
                              logging.warning(f"[!] Warning: EIP is {actual_next_addr:#x}, expected {expected_next_addr:#x}. Control flow changed?")
                         self.current_addr = actual_next_addr

                    # print(f"[*] Next instruction address: {self.current_addr:#x}") # Debug

                except EOFError:
                    logging.error("[-] EOF received, quitting.")
                    break # Exit loop on Ctrl+D
                except KeyboardInterrupt:
                    logging.error("[-] Keyboard interrupt received, quitting.")
                    # Optionally try to detach or kill child cleanly?
                    break # Exit loop on Ctrl+C
                except Exception as loop_e:
                    logging.error(f"[-] Error during interaction loop: {loop_e}")
                    # Decide whether to continue or break
                    break

        finally:
            # Cleanup resources
            self.cleanup()


    def __prompt(self):
        """Displays the input prompt."""
        # Show current address in prompt
        prompt_addr = f"{self.current_addr:#x}"
        if self.__in_block:
            print(f"{prompt_addr}... ", end="")
        else:
            print(f"{prompt_addr}> ", end="")
        sys.stdout.flush() # Ensure prompt appears before input
        return input()

    def cleanup(self):
        """Clean up resources like child process and temporary file."""
        logging.info("[*] Cleaning up...")
        # Detach or kill child process if running
        if self.child_pid > 0:
            try:
                # Check if process still exists before trying to detach/kill
                os.kill(self.child_pid, 0) # Check existence without sending signal
                logging.info(f"[*] Detaching from child process {self.child_pid}...")
                self.ptrace.detach(self.child_pid)
                # Give it a moment to exit after detach? Or just kill?
                # os.kill(self.child_pid, signal.SIGKILL) # Force kill if needed
            except ProcessLookupError:
                logging.info(f"[*] Child process {self.child_pid} already exited.")
            except OSError as e:
                 # Ignore ESRCH if detach failed because it was already gone
                 if e.errno != errno.ESRCH:
                      logging.error(f"[-] Error detaching/killing child process {self.child_pid}: {e}")
            except Exception as e:
                logging.error(f"[-] Unexpected error during child cleanup: {e}")
            self.child_pid = -1

        # Close and delete the temporary executable file
        if self.exe_file_obj is not None:
             RappelExe.cleanup(self.exe_file_obj)
             self.exe_file_obj = None
             self.exe_fd = -1
             self.exe_path = None
        elif self.exe_path and os.path.exists(self.exe_path): # Fallback if fd_obj is lost
             try:
                 os.unlink(self.exe_path)
                 logging.info(f"[*] Cleaned up executable file: {self.exe_path}")
             except OSError as e:
                 logging.warning(f"[!] Failed to cleanup executable '{self.exe_path}': {e}")

        logging.info("[*] Cleanup finished.")

# endregion





# region START RAPPEL
def main(args):
    settings["arch"] = args.arch
    try:
        settings["start_addr"] = int(args.start_addr, 0) # Allow 0x prefix or decimal
    except ValueError:
        logging.error(f"[-] Invalid start address format: '{args.start_addr}'. Use hex (0x...) or decimal.")
        sys.exit(1)
    settings["all_regs"] = args.all_regs

    # Update global arch setting for PTRACE WORD_SIZE etc.
    global WORD_SIZE, PACK_FMT, PACK_SIZE
    WORD_SIZE = 8 if settings['arch'] == 'x64' else 4
    PACK_FMT = '<Q' if settings['arch'] == 'x64' else '<I'
    PACK_SIZE = 8 if settings['arch'] == 'x64' else 4


    print("--- PyRappel Interactive Assembler ---")
    print(f"Architecture: {settings['arch']}")
    print(f"Start Address: {settings['start_addr']:#x}")
    print(f"Show All Regs: {settings['all_regs']}")
    print(f"Temp Dir: {settings['path']}")
    print(f"Page Size: {PAGE_SIZE}")
    print("-" * 38)


    rappel = Rappel(settings['arch'])
    rappel.interact()

    # Cleanup of other temp files in 'bin' (optional, Rappel instance handles its own file)
    # Note: The original code's cleanup might delete unrelated files if not careful.
    # It's safer to rely on the instance cleanup via RappelExe.cleanup.
    # Example of more targeted cleanup if needed:
    # for f in os.listdir(settings['path']):
    #     if f.startswith('rappel-exe.'):
    #         try:
    #             os.unlink(os.path.join(settings['path'], f))
    #         except OSError:
    #             pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Interactive Assembler with Ptrace")
    parser.add_argument('-a', '--arch', type=str, default='x64', choices=['x86', 'x64'],
                        help='Target architecture (x86 or x64)')
    parser.add_argument('-s', '--start-addr', type=str, default=f"{settings['start_addr']:#x}",
                        help='Start virtual address for code execution (e.g., 0x400000)')
    parser.add_argument('-A', '--all-regs', action='store_true', default=False,
                        help='Display all available registers (including FP/SSE)')
    parser.add_argument('-v','--verbose', action='store_true', help='Enable verbose output')
    # Add option for temporary file directory?
    # parser.add_argument('-T', '--temp-dir', type=str, default=settings['path'],
    #                     help='Directory for temporary executable file')

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING
    )

    main(args)
# endregion