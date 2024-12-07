# region BINARY CREATION
from ctypes import c_uint32, c_uint8, c_uint16, c_int16, c_int32, c_uint64, c_int64, c_size_t
from ctypes import Structure
from ctypes import create_string_buffer, cast, POINTER, sizeof, memset, memmove, addressof

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

        with open(self.out, 'wb') as f:
            f.write(e.raw)
        f.close()
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

        with open(self.out, 'wb') as f:
            f.write(e.raw)
        f.close()
        return size
# endregion