from ctypes import *
from .config import PAGE_SIZE, TRAP, settings

EM_X86_64 = 62
EM_386 = 3

Elf32_Addr  = c_uint32
Elf32_Half  = c_uint16
Elf32_Off   = c_uint32
Elf32_Sword = c_int32
Elf32_Word  = c_uint32

Elf64_Addr  = c_uint64
Elf64_Half  = c_uint16
Elf64_SHalf = c_int16
Elf64_Off   = c_uint64
Elf64_Sword = c_int32
Elf64_Word  = c_uint32
Elf64_Xword = c_uint64
Elf64_Sxword = c_int64

ET_EXEC = 2
PT_LOAD = 1

EI_NIDENT = 16

class Elf32_Ehdr(Structure):
    _fields_ = [
        ('e_ident', c_uint8 * EI_NIDENT), ('e_type', Elf32_Half), ('e_machine', Elf32_Half),
        ('e_version', Elf32_Word), ('e_entry', Elf32_Addr), ('e_phoff', Elf32_Off),
        ('e_shoff', Elf32_Off), ('e_flags', Elf32_Word), ('e_ehsize', Elf32_Half),
        ('e_phentsize', Elf32_Half), ('e_phnum', Elf32_Half), ('e_shentsize', Elf32_Half),
        ('e_shnum', Elf32_Half), ('e_shstrndx', Elf32_Half)
    ]

class Elf64_Ehdr(Structure):
    _fields_ = [
        ('e_ident', c_uint8 * EI_NIDENT), ('e_type', Elf64_Half), ('e_machine', Elf64_Half),
        ('e_version', Elf64_Word), ('e_entry', Elf64_Addr), ('e_phoff', Elf64_Off),
        ('e_shoff', Elf64_Off), ('e_flags', Elf64_Word), ('e_ehsize', Elf64_Half),
        ('e_phentsize', Elf64_Half), ('e_phnum', Elf64_Half), ('e_shentsize', Elf64_Half),
        ('e_shnum', Elf64_Half), ('e_shstrndx', Elf64_Half)
    ]

PF_R = 0x4
PF_W = 0x2
PF_X = 0x1

class Elf32_Phdr(Structure):
    _fields_ = [
        ('p_type', Elf32_Word), ('p_offset', Elf32_Off), ('p_vaddr', Elf32_Addr),
        ('p_paddr', Elf32_Addr), ('p_filesz', Elf32_Word), ('p_memsz', Elf32_Word),
        ('p_flags', Elf32_Word), ('p_align', Elf32_Word)
    ]

class Elf64_Phdr(Structure):
    _fields_ = [
        ('p_type', Elf64_Word), ('p_flags', Elf64_Word), ('p_offset', Elf64_Off),
        ('p_vaddr', Elf64_Addr), ('p_paddr', Elf64_Addr), ('p_filesz', Elf64_Xword),
        ('p_memsz', Elf64_Xword), ('p_align', Elf64_Xword)
    ]

ELFMAG0 = 0x7f
ELFMAG1 = ord('E')
ELFMAG2 = ord('L')
ELFMAG3 = ord('F')

ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1
ELFOSABI_NONE = 0


class ELF:
    def __init__(self, arch, out=None, start=None, code=None, code_size=None):
        self.arch = arch
        self.out = out
        self.start = start if start is not None else settings['start_addr']
        self.code = code
        self.code_size = code_size if code_size is not None else PAGE_SIZE

    def gen_elf(self):
        if self.arch == 'x86':
            return self.__gen_elf32()
        elif self.arch == 'x64':
            return self.__gen_elf64()
        else:
            raise ValueError(f'Unsupported architecture: {self.arch}')

    def __gen_elf32(self):
        ehdr_size = sizeof(Elf32_Ehdr)
        phdr_size = sizeof(Elf32_Phdr)
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
        ehdr = cast(e, POINTER(Elf32_Ehdr)).contents
        ehdr.e_ident[0:4] = bytes([ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3])
        ehdr.e_ident[4] = ELFCLASS32
        ehdr.e_ident[5] = ELFDATA2LSB
        ehdr.e_ident[6] = EV_CURRENT
        ehdr.e_ident[7] = ELFOSABI_NONE
        ehdr.e_type = ET_EXEC
        ehdr.e_machine = EM_386
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
        phdr = cast(phdr_address, POINTER(Elf32_Phdr)).contents
        phdr.p_type = PT_LOAD
        phdr.p_flags = PF_X | PF_R | PF_W
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
        ehdr = cast(e, POINTER(Elf64_Ehdr)).contents
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
        phdr = cast(phdr_address, POINTER(Elf64_Phdr)).contents
        phdr.p_type = PT_LOAD
        phdr.p_flags = PF_X | PF_R | PF_W
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

import ctypes
from ctypes import *

from .config import PAGE_SIZE, TRAP


# region ELF constants and structures
# elf-em.h
EM_X86_64 = 62
EM_386 = 3

# elf.h base types
Elf32_Addr = c_uint32
Elf32_Half = c_uint16
Elf32_Off = c_uint32
Elf32_Sword = c_int32
Elf32_Word = c_uint32

Elf64_Addr = c_uint64
Elf64_Half = c_uint16
Elf64_SHalf = c_int16
Elf64_Off = c_uint64
Elf64_Sword = c_int32
Elf64_Word = c_uint32
Elf64_Xword = c_uint64
Elf64_Sxword = c_int64

ET_EXEC = 2
PT_LOAD = 1

EI_NIDENT = 16


class Elf32_Ehdr(Structure):
    _fields_ = [
        ('e_ident', c_uint8 * EI_NIDENT),
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
        ('e_ident', c_uint8 * EI_NIDENT),
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
        ('p_offset', Elf64_Off),
        ('p_vaddr', Elf64_Addr),
        ('p_paddr', Elf64_Addr),
        ('p_filesz', Elf64_Xword),
        ('p_memsz', Elf64_Xword),
        ('p_align', Elf64_Xword)
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
# endregion


# region Strategy pattern for ELF generation
class ElfGeneratorStrategy:
    def generate(self, start: int, code: bytes, code_size: int) -> tuple[bytes, int]:
        raise NotImplementedError


class Elf32Generator(ElfGeneratorStrategy):
    def generate(self, start: int, code: bytes, code_size: int) -> tuple[bytes, int]:
        ehdr_size = sizeof(Elf32_Ehdr)
        phdr_size = sizeof(Elf32_Phdr)
        num_phdrs = 1

        page_mask = PAGE_SIZE - 1
        pg_offset = start & page_mask
        segment_vaddr = start - pg_offset
        segment_offset = PAGE_SIZE

        header_total_size = ehdr_size + phdr_size * num_phdrs
        if header_total_size > PAGE_SIZE:
            raise ValueError("ELF headers too large for a single page")

        segment_filesz = pg_offset + code_size
        segment_memsz = segment_filesz
        total_file_size = segment_offset + segment_filesz

        e = create_string_buffer(total_file_size)
        memset(e, 0, total_file_size)
        memset(addressof(e) + segment_offset + pg_offset, TRAP, code_size)

        ehdr: Elf32_Ehdr = cast(e, POINTER(Elf32_Ehdr)).contents
        ehdr.e_ident[0:4] = bytes([ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3])
        ehdr.e_ident[4] = ELFCLASS32
        ehdr.e_ident[5] = ELFDATA2LSB
        ehdr.e_ident[6] = EV_CURRENT
        ehdr.e_ident[7] = ELFOSABI_NONE
        ehdr.e_type = ET_EXEC
        ehdr.e_machine = EM_386
        ehdr.e_version = EV_CURRENT
        ehdr.e_entry = start
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
        phdr: Elf32_Phdr = cast(phdr_address, POINTER(Elf32_Phdr)).contents
        phdr.p_type = PT_LOAD
        phdr.p_flags = PF_X | PF_R | PF_W
        phdr.p_offset = segment_offset
        phdr.p_vaddr = segment_vaddr
        phdr.p_paddr = 0
        phdr.p_filesz = segment_filesz
        phdr.p_memsz = segment_memsz
        phdr.p_align = PAGE_SIZE

        if code:
            code_dest_offset = segment_offset + pg_offset
            copy_size = min(len(code), code_size)
            memmove(addressof(e) + code_dest_offset, code, copy_size)

        return e.raw, total_file_size


class Elf64Generator(ElfGeneratorStrategy):
    def generate(self, start: int, code: bytes, code_size: int) -> tuple[bytes, int]:
        ehdr_size = sizeof(Elf64_Ehdr)
        phdr_size = sizeof(Elf64_Phdr)
        num_phdrs = 1

        page_mask = PAGE_SIZE - 1
        pg_offset = start & page_mask
        segment_vaddr = start - pg_offset
        segment_offset = PAGE_SIZE

        header_total_size = ehdr_size + phdr_size * num_phdrs
        if header_total_size > PAGE_SIZE:
            raise ValueError("ELF headers too large for a single page")

        segment_filesz = pg_offset + code_size
        segment_memsz = segment_filesz
        total_file_size = segment_offset + segment_filesz

        e = create_string_buffer(total_file_size)
        memset(e, 0, total_file_size)
        memset(addressof(e) + segment_offset + pg_offset, TRAP, code_size)

        ehdr: Elf64_Ehdr = cast(e, POINTER(Elf64_Ehdr)).contents
        ehdr.e_ident[0:4] = bytes([ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3])
        ehdr.e_ident[4] = ELFCLASS64
        ehdr.e_ident[5] = ELFDATA2LSB
        ehdr.e_ident[6] = EV_CURRENT
        ehdr.e_ident[7] = ELFOSABI_NONE
        ehdr.e_type = ET_EXEC
        ehdr.e_machine = EM_X86_64
        ehdr.e_version = EV_CURRENT
        ehdr.e_entry = start
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
        phdr.p_flags = PF_X | PF_R | PF_W
        phdr.p_offset = segment_offset
        phdr.p_vaddr = segment_vaddr
        phdr.p_paddr = 0
        phdr.p_filesz = segment_filesz
        phdr.p_memsz = segment_memsz
        phdr.p_align = PAGE_SIZE

        if code:
            code_dest_offset = segment_offset + pg_offset
            copy_size = min(len(code), code_size)
            memmove(addressof(e) + code_dest_offset, code, copy_size)

        return e.raw, total_file_size


class ElfGeneratorFactory:
    @staticmethod
    def create(arch: str) -> ElfGeneratorStrategy:
        if arch == 'x86':
            return Elf32Generator()
        if arch == 'x64':
            return Elf64Generator()
        raise ValueError(f"Unsupported architecture: {arch}")


def build_minimal_elf(arch: str, start: int, code: bytes, code_size: int) -> tuple[bytes, int]:
    strategy = ElfGeneratorFactory.create(arch)
    return strategy.generate(start=start, code=code, code_size=code_size)


