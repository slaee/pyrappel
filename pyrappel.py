#!.venv/bin/python3.12

# region RAPPEL SETTINGS
import os
user_path = os.getenv('HOME')

settings = {
    # 'path': f'{user_path}/.rappel/exe',
    'path': 'bin',
    'start_addr': 0x400000,
    'arch': 'x86',
}
# endregion




# region IMPORTS
import sys
import ctypes.util
import signal
import stat
import tempfile
import keystone

from ctypes import *
# endregion




# region BINARY GENERATION
# Page size of the system
PAGE_SIZE   = 1 << 12

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
        ('e_ident', c_uint8 * EI_NIDENT), # Elf32_Ehdr.e_ident[EI_NIDENT]
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
ELFOSABI_NONE = 0

TRAP = 0xcc

class ELF:
    def __init__(self, arch, out=None, start=None, code=None, code_size=None):
        self.arch = arch
        self.out = out
        self.start = start
        self.code = code
        self.code_size = code_size

    def gen_elf(self):
        """
        We give the elf header and phdr an entire page, because the elf loader can
        only map the file at PAGE_SIZE offsets. So our file will look like this 
        for an invocation with some code and 2 data segments.
        
        * +----------+
        * | 1st page |
        * | ehdr     |
        * | phdr     |
        * | shdr     |
        * | shdr     |
        * |----------|
        * | 2nd page |
        * | code     |
        * |----------|
        * | 3rd page |
        * | data 1   |
        * |----------|
        * | 4th page |
        * | data 2   |
        * +----------+
        
        TODO add data section, section headers
        """
        if self.arch == 32:
            return self.__gen_elf32()
        elif self.arch == 64:
            return self.__gen_elf64()
        else:
            raise ValueError('Unknown architecture')
        
    def __gen_elf32(self):
        pg_align_dist: c_size_t = self.start - (self.start & ~0xffff)
        pad_size: c_size_t = ((self.code_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)) - self.code_size
        size: c_size_t = PAGE_SIZE + pg_align_dist + self.code_size + pad_size

        e = create_string_buffer(size)
        memset(e, TRAP, size)

        # e: c_uint8 = create_string_buffer(size)
        ehdr: Elf32_Ehdr = cast(e, POINTER(Elf32_Ehdr)).contents

        ehdr.e_ident[0] = ELFMAG0
        ehdr.e_ident[1] = ELFMAG1
        ehdr.e_ident[2] = ELFMAG2
        ehdr.e_ident[3] = ELFMAG3
        ehdr.e_ident[4] = ELFCLASS32
        ehdr.e_ident[5] = ELFDATA2LSB
        ehdr.e_ident[6] = EV_CURRENT
        ehdr.e_ident[7] = ELFOSABI_NONE
        ehdr.e_ident[8:16] = [0] * 8
        # Padding
        ehdr.e_type = ET_EXEC
        ehdr.e_machine = EM_386
        ehdr.e_version = EV_CURRENT
        ehdr.e_entry = self.start
        ehdr.e_phoff = sizeof(Elf32_Ehdr)
        ehdr.e_shoff = 0
        ehdr.e_flags = 0
        ehdr.e_ehsize = sizeof(Elf32_Ehdr)
        ehdr.e_phentsize = sizeof(Elf32_Phdr)
        ehdr.e_phnum = 1
        ehdr.e_shentsize = 0
        ehdr.e_shnum = 0
        ehdr.e_shstrndx = 0
        
        phdr_addess = addressof(e) + sizeof(Elf32_Ehdr)
        phdr: Elf32_Phdr = cast(phdr_addess, POINTER(Elf32_Phdr)).contents
        phdr.p_type = PT_LOAD
        phdr.p_flags = PF_X | PF_R
        phdr.p_offset = PAGE_SIZE
        phdr.p_vaddr = self.start - pg_align_dist
        phdr.p_paddr = 0
        phdr.p_filesz = self.code_size + pg_align_dist
        phdr.p_memsz = self.code_size + pg_align_dist
        phdr.p_align = 0x4

        # Copy code into the ELF file at the appropriate offset
        data: c_uint8 = cast(e[phdr.p_offset:], POINTER(c_uint8))
        memmove(data, self.code, self.code_size)

        self.out = e.raw
        return size

    def __gen_elf64(self):
        pg_align_dist: c_size_t = self.start - (self.start & ~0xffff)
        pad_size: c_size_t = ((self.code_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)) - self.code_size
        size: c_size_t = PAGE_SIZE + pg_align_dist + self.code_size + pad_size

        e = create_string_buffer(size)
        memset(e, TRAP, size)

        # e: c_uint8 = create_string_buffer(size)
        ehdr: Elf64_Ehdr = cast(e, POINTER(Elf64_Ehdr)).contents

        ehdr.e_ident[0] = ELFMAG0
        ehdr.e_ident[1] = ELFMAG1
        ehdr.e_ident[2] = ELFMAG2
        ehdr.e_ident[3] = ELFMAG3
        ehdr.e_ident[4] = ELFCLASS64
        ehdr.e_ident[5] = ELFDATA2LSB
        ehdr.e_ident[6] = EV_CURRENT
        ehdr.e_ident[7] = ELFOSABI_NONE
        # Padding
        ehdr.e_ident[8:16] = [0] * 8
        ehdr.e_type = ET_EXEC
        ehdr.e_machine = EM_X86_64
        ehdr.e_version = EV_CURRENT
        ehdr.e_entry = self.start
        ehdr.e_phoff = sizeof(Elf64_Ehdr)
        ehdr.e_shoff = 0
        ehdr.e_flags = 0
        ehdr.e_ehsize = sizeof(Elf32_Ehdr)
        ehdr.e_phentsize = sizeof(Elf64_Phdr)
        ehdr.e_phnum = 1
        ehdr.e_shentsize = 0
        ehdr.e_shnum = 0
        ehdr.e_shstrndx = 0
        
        phdr_addess = addressof(e) + sizeof(Elf64_Ehdr)
        phdr: Elf32_Phdr = cast(phdr_addess, POINTER(Elf64_Phdr)).contents
        phdr.p_type = PT_LOAD
        phdr.p_flags = PF_X | PF_R
        phdr.p_offset = PAGE_SIZE
        phdr.p_vaddr = self.start - pg_align_dist
        phdr.p_paddr = 0
        phdr.p_filesz = self.code_size + pg_align_dist
        phdr.p_memsz = self.code_size + pg_align_dist
        phdr.p_align = 0x4

        # Copy code into the ELF file at the appropriate offset
        data: c_uint8 = cast(e[phdr.p_offset:], POINTER(c_uint8))
        memmove(data, self.code, self.code_size)

        self.out = e.raw
        return size
# endregion




# region RAPPEL EXE WRITER
class RappelExe:
    @staticmethod
    def write(data, path=None):
        if path is not None:
            return RappelExe.__write_file(data, path)
        else:
            return RappelExe.__write_tmp_file(data)
        
    @staticmethod
    def __write_file(data, path):
        try:
            fd = os.open(path, os.O_CREAT | os.O_WRONLY | stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)

            if fd >= 0:
                os.write(fd, data)
                return RappelExe.__reopen_ro(fd, path)
            else:
                raise OSError(f"Failed to open {path} for writing: {os.strerror(ctypes.get_errno())}")          
        except Exception as e:
            print(f"[-] Error writing to {path}: {e}")

    @staticmethod
    def __write_tmp_file(data):
        try:
            fd, path = tempfile.mkstemp(prefix='rappel-exe.', dir=settings.get('path'))
            if fd >= 0:
                os.write(fd, data)
                os.fchmod(fd, stat.S_IXUSR | stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)

                return RappelExe.__reopen_ro(fd, path)
            else:
                raise OSError(f"Failed to open temporary file for writing: {os.strerror(ctypes.get_errno())}")
        except Exception as e:
            print(f"[-] Error writing to temporary file: {e}")

    @staticmethod
    def __reopen_ro(fd, path):
        try:
            os.close(fd)
            ro_fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)

            if ro_fd < 0:
                raise OSError(f"Failed to reopen {path} read-only: {os.strerror(ctypes.get_errno())}")
            
            return ro_fd
        except Exception as e:
            print(f"[-] Error reopening {path} read-only: {e}")
# endregion




# region RAPPEL KEYSTONE
class RappelKeystone:
    def __init__(self, arch, mode):
        self.arch = arch
        self.mode = mode
        self.ks = None

        if arch == 'x86':
            if mode == '32':
                self.ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
            elif mode == '64':
                self.ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
            else:
                raise ValueError('Unknown mode')
        else:
            raise ValueError('Unknown architecture')
        
    def assemble(self, code: str) -> bytes:
        """Assemble the given code into machine code."""
        try:
            encoding, count = self.ks.asm(code)
            print(f"[+] Assembled {count} instructions.")
            return bytes(encoding)
        except keystone.KsError as e:
            print(f"[-] Keystone error: {e}")
            raise
# endregion




# region UTIL FUNCTIONS
REGFMT64 = "{:016x}"  # Equivalent to "%016x" in C (64-bit)
REGFMT32 = "{:08x}"   # Equivalent to "%08x" in C (32-bit)
REGFMT16 = "{:04x}"   # Equivalent to "%04x" in C (16-bit)
REGFMT8  = "{:02x}"   # Equivalent to "%02x" in C (8-bit)

RED = "\033[31m"     # ANSI escape code for red text
RST = "\033[0m"      # ANSI reset code

def dump_reg64(x_name, y, z):
    """
    Mimics DUMPREG64 macro functionality.
    Prints the value of the register in red if it differs from z.x, otherwise normal formatting.
    """
    y_value = getattr(y, x_name)
    z_value = getattr(z, x_name)
    
    if y_value == z_value:
        print(REGFMT64.format(y_value), end="")
    else:
        print(f"{RED}{REGFMT64.format(y_value)}{RST}", end="")

def print_reg64(header, x_name, y, z, trailer):
    """
    Mimics PRINTREG64 macro functionality.
    Prints a header, followed by the register value, and a trailer.
    """
    print(header, end="")
    dump_reg64(x_name, y, z)
    print(trailer, end="")

def dump_reg32(x_name, y, z):
    """
    Mimics DUMPREG32 macro functionality.
    Prints the value of the register in red if it differs from z.x, otherwise normal formatting.
    """
    y_value = getattr(y, x_name)
    z_value = getattr(z, x_name)
    
    if y_value == z_value:
        print(REGFMT32.format(y_value), end="")
    else:
        print(f"{RED}{REGFMT32.format(y_value)}{RST}", end="")

def print_reg32(header, x_name, y, z, trailer):
    """
    Mimics PRINTREG32 macro functionality.
    Prints a header, followed by the register value, and a trailer.
    """
    print(header, end="")
    dump_reg32(x_name, y, z)
    print(trailer, end="")

def dump_reg16(x_name, y, z):
    """
    Mimics DUMPREG16 macro functionality.
    Prints the value of the register in red if it differs from z.x, otherwise normal formatting.
    """
    y_value = getattr(y, x_name)
    z_value = getattr(z, x_name)
    
    if y_value == z_value:
        print(REGFMT16.format(y_value), end="")
    else:
        print(f"{RED}{REGFMT16.format(y_value)}{RST}", end="")

def print_reg16(header, x_name, y, z, trailer):
    """
    Mimics PRINTREG16 macro functionality.
    Prints a header, followed by the register value, and a trailer.
    """
    print(header, end="")
    dump_reg16(x_name, y, z)
    print(trailer, end="")

def dump_reg8(x_name, y, z):
    """
    Mimics DUMPREG8 macro functionality.
    Prints the value of the register in red if it differs from z.x, otherwise normal formatting.
    """
    y_value = getattr(y, x_name)
    z_value = getattr(z, x_name)
    
    if y_value == z_value:
        print(REGFMT8.format(y_value), end="")
    else:
        print(f"{RED}{REGFMT8.format(y_value)}{RST}", end="")

def print_reg8(header, x_name, y, z, trailer):
    """
    Mimics PRINTREG8 macro functionality.
    Prints a header, followed by the register value, and a trailer.
    """
    print(header, end="")
    dump_reg8(x_name, y, z)
    print(trailer, end="")

def print_bit(name, y, z, trailer):
    """
    Mimics PRINTBIT macro functionality.
    Prints the value of the bit in red if it differs from z, otherwise normal formatting.
    """
    if y == z:
        print(f"{name}{y}", end="")
    else:
        print(f"{RED}{name}{y}{RST}", end="")
    print(trailer, end="")
# endregion




# region ARCH STRUCTURES
class user_fpregs_struct_x86(Structure):
    _fields_ = [
        ('cwd', c_int32),
        ('swd', c_int32),
        ('twd', c_int32),
        ('fip', c_int32),
        ('fcs', c_int32),
        ('foo', c_int32),
        ('fos', c_int32),
        ('st_space', c_int32 * 20),
    ]

class user_fpxregs_struct_x86(Structure):
    _fields_ = [
        ('cwd', c_ushort),
        ('swd', c_ushort),
        ('twd', c_ushort),
        ('fop', c_ushort),
        ('fip', c_int32),
        ('fcs', c_int32),
        ('foo', c_int32),
        ('fos', c_int32),
        ('mxcsr', c_int32),
        ('reserved', c_int32),
        ('st_space', c_int32 * 32),
        ('xmm_space', c_int32 * 32),
        ('padding', c_int32 * 56),
    ]

class user_regs_struct_x86(Structure):
    _fields_ = [
        ('ebx', c_int32),
        ('ecx', c_int32),
        ('edx', c_int32),
        ('esi', c_int32),
        ('edi', c_int32),
        ('ebp', c_int32),
        ('eax', c_int32),
        ('xds', c_int32),
        ('xes', c_int32),
        ('xfs', c_int32),
        ('xgs', c_int32),
        ('orig_eax', c_int32),
        ('eip', c_int32),
        ('xcs', c_int32),
        ('eflags', c_int32),
        ('esp', c_uint32),
        ('xss', c_int32)
    ]

class IOVec(Structure):
    _fields_ = [
        ("iov_base", c_void_p),  # Pointer to the data
        ("iov_len", c_size_t),  # Length of the data
    ]

class proc_info_t(Structure):
    _fields_ = [
        ('pid', c_long),
        ('regs_struct', user_regs_struct_x86),
        ('old_regs_struct', user_regs_struct_x86),
        ('regs', IOVec),

        ('fpregs_struct', user_fpregs_struct_x86),
        ('old_fpregs_struct', user_fpregs_struct_x86),
        ('fpregs', IOVec),

        ('fpxregs_struct', user_fpxregs_struct_x86),
        ('old_fpxregs_struct', user_fpxregs_struct_x86),
        ('fpxregs', IOVec),

        ('sig', c_int),
        ('exit_code', c_int),
    ]
# endregion




# region RAPPEL PTRACE

# We need to use the libc library to call ptrace instead of using the ptrace module
libc = CDLL(ctypes.util.find_library("c"), use_errno=True)

# ptrace(2) constants from sys/ptrace.h
PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_EVENT_EXIT = 6
PTRACE_CONT = 7
PTRACE_DETACH = 17
PTRACE_O_TRACEEXIT = 64
PTRACE_SETOPTIONS = 0x4200
PTRACE_GETEVENTMSG = 0x4201
PTRACE_GETSIGINFO = 0x4202
PTRACE_GETREGSET = 0x4204

NT_PRSTATUS = 1
NT_PRFPREG = 2
NT_PRXFPREG = 0x46e62b7f

class Ptrace:
    def child(self, exe_fd):
        try:
            libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
            argv = (c_char_p * 1)(None)
            env = (c_char_p * 1)(None)
            libc.fexecve(exe_fd, argv, env)
        except Exception as e:
            print(f"[-] Error starting process: {e}")
            sys.exit(1)

    def launch(self, pid):
        try:
            # waitpid(2) status
            status = ctypes.c_int32(0)
            libc.waitpid(pid, ctypes.byref(status), 0)
            
            if os.WIFEXITED(status.value):
                print("[+] Process exited normally.")
            
            libc.ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXIT)
        except Exception as e:
            print(f"[-] Error continuing process: {e}")
            sys.exit(1)

    def cont(self, pid, info: proc_info_t):
        try:
            self.__ptrace_collect_regs(pid, info)
            libc.ptrace(PTRACE_CONT, pid, 0, 0)
        except Exception as e:
            print(f"[-] Error continuing process: {e}")
            sys.exit(1)

    def reap(self, pid, info: proc_info_t):
        try:
            status = ctypes.c_int32(0)
            libc.waitpid(pid, ctypes.byref(status), 0)

            if os.WIFEXITED(status.value):
                print("[+] Process exited normally.")
                return 1

            if os.WIFSIGNALED(status.value):
                print(f"[-] Process exited with signal {status.value & 0x7f}")
                info.sig = status.value & 0x7f
                return 1

            if status.value >> 8 == (signal.SIGTRAP | (PTRACE_EVENT_EXIT << 8)):
                self.__exited_collect_regs(pid, info)
                return 1
            
            self.__ptrace_collect_regs(pid, info)

            if status.value >> 8 == signal.SIGTRAP:
                return 0
            
        except Exception as e:
            print(f"[-] Error reaping process: {e}")
            sys.exit(1)

    def init_proc_info(self, info: proc_info_t):
        info.regs.iov_base = ctypes.addressof(info.regs_struct)
        info.regs.iov_len = sizeof(info.regs_struct)

        info.fpregs.iov_base = ctypes.addressof(info.fpregs_struct)
        info.fpregs.iov_len = sizeof(info.fpregs_struct)

        info.fpxregs.iov_base = ctypes.addressof(info.fpxregs_struct)
        info.fpxregs.iov_len = sizeof(info.fpxregs_struct)

    def __exited_collect_regs(self, pid, info: proc_info_t):
        self.__ptrace_collect_regs(pid, info)
        
        sig = c_int(0)
        libc.ptrace(PTRACE_GETSIGINFO, pid, None, ctypes.byref(sig))

        info.sig = sig.value

        libc.ptrace(PTRACE_GETEVENTMSG, pid, None, ctypes.byref(info.exit_code))

    def __ptrace_collect_regs(self, pid, info: proc_info_t):
        info.pid = pid

        info.old_regs_struct = info.regs_struct
        libc.ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, ctypes.byref(info.regs))
        
        info.old_fpregs_struct = info.fpregs_struct
        libc.ptrace(PTRACE_GETREGSET, pid, NT_PRFPREG, ctypes.byref(info.fpregs))
        
        info.old_fpxregs_struct = info.fpxregs_struct
        libc.ptrace(PTRACE_GETREGSET, pid, NT_PRXFPREG, ctypes.byref(info.fpxregs))

        info.sig = -1
        info.exit_code = -1
# endregion


# region RAPPEL UI
class Rappel:
    def __init__(self, arch=64):
        self.arch = arch
        self.ptrace = Ptrace()

        buffer: Array = create_string_buffer(PAGE_SIZE)
        memset(buffer, TRAP, PAGE_SIZE)

        if arch == 32:
            # Create an ELF object
            elf = ELF(32)
            elf.start = settings.get('start_addr')
            elf.code = buffer
            elf.code_size = PAGE_SIZE
            elf.gen_elf()
            # Generate the ELF file
            self.exe_fd = RappelExe.write(elf.out)
            del elf
            self.keystone = RappelKeystone('x86', '32')
        elif arch == 64:
            elf = ELF(64)
            elf.start = settings.get('start_addr')
            elf.code = buffer
            elf.code_size = PAGE_SIZE
            elf.gen_elf()
            # Generate the ELF file
            self.exe_fd = RappelExe.write(elf.out)
            del elf
            self.keystone = RappelKeystone('x86', '64')
        else:
            raise ValueError('Unknown architecture')
        
    def __trace_child(self):
        try:
            trace_pid = os.fork()
            if trace_pid == 0:
                self.ptrace.child(self.exe_fd)
                os.abort()
            elif trace_pid < 0:
                raise OSError(f"Failed to fork: {os.strerror(ctypes.get_errno())}")
            
            os.close(self.exe_fd)
            return trace_pid
        except Exception as e:
            print(f"[-] Error forking: {e}")
            return None
        
    def display_info(self, info: proc_info_t):
        regs: user_regs_struct_x86 = info.regs_struct
        fpregs: user_fpregs_struct_x86 = info.fpregs_struct
        fpxregs: user_fpxregs_struct_x86 = info.fpxregs_struct

        old_regs: user_regs_struct_x86 = info.old_regs_struct
        old_fpregs: user_fpregs_struct_x86 = info.old_fpregs_struct
        old_fpxregs: user_fpxregs_struct_x86 = info.old_fpxregs_struct

        print_reg32("eax=", "eax", regs, old_regs, " ")
        print_reg32("ebx=", "ebx", regs, old_regs, " ")
        print_reg32("ecx=", "ecx", regs, old_regs, " ")
        print_reg32("edx=", "edx", regs, old_regs, " ")
        print_reg32("esi=", "esi", regs, old_regs, " ")
        print_reg32("edi=", "edi", regs, old_regs, "\n")

        print_reg32("eip=", "eip", regs, old_regs, " ")
        print_reg32("esp=", "esp", regs, old_regs, " ")
        print_reg32("ebp=", "ebp", regs, old_regs, " ")

        of: c_uint8 = (regs.eflags & 0x800) >> 11
        old_of: c_uint8 = (old_regs.eflags & 0x800) >> 11

        df: c_uint8 = (regs.eflags & 0x400) >> 10
        old_df: c_uint8 = (old_regs.eflags & 0x400) >> 10

        sf: c_uint8 = (regs.eflags & 0x80) >> 7
        old_sf: c_uint8 = (old_regs.eflags & 0x80) >> 7

        zf: c_uint8 = (regs.eflags & 0x40) >> 6
        old_zf: c_uint8 = (old_regs.eflags & 0x40) >> 6

        af: c_uint8 = (regs.eflags & 0x10) >> 4
        old_af: c_uint8 = (old_regs.eflags & 0x10) >> 4

        pf: c_uint8 = (regs.eflags & 0x4) >> 2
        old_pf: c_uint8 = (old_regs.eflags & 0x4) >> 2

        cf: c_uint8 = (regs.eflags & 0x1)
        old_cf: c_uint8 = (old_regs.eflags & 0x1)

        print_bit("[cf:", cf, old_cf, ", ")
        print_bit("zf:", zf, old_zf, ", ")
        print_bit("of:", of, old_of, ", ")
        print_bit("sf:", sf, old_sf, ", ")
        print_bit("pf:", pf, old_pf, ", ")
        print_bit("af:", af, old_af, ", ")
        print_bit("df:", df, old_df, "]\n")

        print_reg16("cs=", "xcs", regs, old_regs, " ")
        print_reg16("ss=", "xss", regs, old_regs, " ")
        print_reg16("ds=", "xds", regs, old_regs, " ")
        print_reg16("es=", "xes", regs, old_regs, " ")
        print_reg16("fs=", "xfs", regs, old_regs, " ")
        print_reg16("gs=", "xgs", regs, old_regs, "          ")

        print_reg32("efl=", "eflags", regs, old_regs, " ")

    
    def interact(self):
        child_pid = self.__trace_child()

        info = proc_info_t()
        self.ptrace.init_proc_info(info)

        self.ptrace.launch(child_pid)
        self.ptrace.cont(child_pid, info)
        self.ptrace.reap(child_pid, info)

        self.display_info(info)
        
# endregion

# region START RAPPEL
def main():
    rappel = Rappel(32)
    rappel.interact()

if __name__ == '__main__':
    main()
    # Delete rapel-exe.* files settings path
    os.system(f'rm -rf {settings.get("path")}/rappel-exe.*')
# endregion