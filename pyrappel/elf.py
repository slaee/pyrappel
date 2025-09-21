from ctypes import c_uint32, c_uint16, c_uint8, c_uint64, c_int32, c_int64, c_int16, Structure, sizeof, create_string_buffer, memset, addressof, memmove, cast, POINTER
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

# Section header constants and structures
SHN_UNDEF = 0
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

class Elf32_Shdr(Structure):
    _fields_ = [
        ('sh_name', Elf32_Word), ('sh_type', Elf32_Word), ('sh_flags', Elf32_Word),
        ('sh_addr', Elf32_Addr), ('sh_offset', Elf32_Off), ('sh_size', Elf32_Word),
        ('sh_link', Elf32_Word), ('sh_info', Elf32_Word), ('sh_addralign', Elf32_Word),
        ('sh_entsize', Elf32_Word)
    ]

class Elf64_Shdr(Structure):
    _fields_ = [
        ('sh_name', Elf64_Word), ('sh_type', Elf64_Word), ('sh_flags', Elf64_Xword),
        ('sh_addr', Elf64_Addr), ('sh_offset', Elf64_Off), ('sh_size', Elf64_Xword),
        ('sh_link', Elf64_Word), ('sh_info', Elf64_Word), ('sh_addralign', Elf64_Xword),
        ('sh_entsize', Elf64_Xword)
    ]


class ELF:
    def __init__(self, arch, out=None, start=None, code=None, code_size=None, data=None, data_size=None):
        self.arch = arch
        self.out = out
        self.start = start if start is not None else settings['start_addr']
        self.code = code
        self.code_size = code_size if code_size is not None else PAGE_SIZE
        self.data = data
        self.data_size = data_size if data_size is not None else 0

    def gen_elf(self):
        if self.arch == 'x86':
            return self.__gen_elf32()
        elif self.arch == 'x64':
            return self.__gen_elf64()
        else:
            raise ValueError(f'Unsupported architecture: {self.arch}')
    """
    We give the elf header and phdr an entire page, because the elf loader can
    only map the file at PAGE_SIZE offsets. So our file will look like this 
	for an invocation with some code and 2 data segments. 
	 +----------+
	 | 1st page |
	 | ehdr     |
	 | phdr     |
	 | shdr     |
	 | shdr     |
	 |----------|
	 | 2nd page |
	 | code     |
	 |----------|
	 | 3rd page |
	 | data 1   |
	 |----------|
	 | 4th page |
	 | data 2   |
	 +----------+
    """

    def __gen_elf32(self):
        ehdr_size = sizeof(Elf32_Ehdr)
        phdr_size = sizeof(Elf32_Phdr)
        num_phdrs = 1
        shdr_size = sizeof(Elf32_Shdr)
        page_mask = PAGE_SIZE - 1
        pg_offset = self.start & page_mask
        segment_vaddr = self.start - pg_offset
        segment_offset = PAGE_SIZE
        # Layout inside segment
        code_file_offset = segment_offset + pg_offset
        code_vaddr = self.start
        code_size = self.code_size
        data_present = bool(self.data and self.data_size and self.data_size > 0)
        data_offset_in_segment = (pg_offset + code_size + (PAGE_SIZE - 1)) & ~page_mask if data_present else (pg_offset + code_size)
        data_file_offset = segment_offset + data_offset_in_segment
        data_vaddr = segment_vaddr + data_offset_in_segment
        data_size = self.data_size if data_present else 0
        segment_filesz = data_offset_in_segment + data_size
        segment_memsz = segment_filesz
        # Section names and shstrtab in first page
        sh_names = [b'', b'.text', b'.data'] if data_present else [b'', b'.text']
        sh_names.append(b'.shstrtab')
        shstrtab_bytes = b'\x00' + b'\x00'.join(name for name in sh_names[1:]) + b'\x00'
        name_offsets = {b'': 0}
        cur = 1
        for name in sh_names[1:]:
            name_offsets[name] = cur
            cur += len(name) + 1
        shnum = 1 + (2 if data_present else 1) + 1
        header_space_used = ehdr_size + (phdr_size * num_phdrs) + (shdr_size * shnum) + len(shstrtab_bytes)
        if header_space_used > PAGE_SIZE:
            raise ValueError("ELF headers+sections too large for a single page")
        shoff = ehdr_size + (phdr_size * num_phdrs)
        shstrtab_offset = shoff + (shdr_size * shnum)
        total_file_size = segment_offset + segment_filesz
        e = create_string_buffer(total_file_size)
        memset(e, 0, total_file_size)
        memset(addressof(e) + code_file_offset, TRAP, code_size)
        memmove(addressof(e) + shstrtab_offset, shstrtab_bytes, len(shstrtab_bytes))
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
        ehdr.e_shoff = shoff
        ehdr.e_flags = 0
        ehdr.e_ehsize = ehdr_size
        ehdr.e_phentsize = phdr_size
        ehdr.e_phnum = num_phdrs
        ehdr.e_shentsize = shdr_size
        ehdr.e_shnum = shnum
        ehdr.e_shstrndx = (2 if data_present else 1) + 1
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
            copy_size = min(len(self.code), code_size)
            memmove(addressof(e) + code_file_offset, self.code, copy_size)
        if data_present:
            if self.data:
                memmove(addressof(e) + data_file_offset, self.data, data_size)
            else:
                memset(addressof(e) + data_file_offset, 0, data_size)
        # Section headers
        shdr_base = addressof(e) + shoff
        sh_null = cast(shdr_base, POINTER(Elf32_Shdr)).contents
        memset(addressof(sh_null), 0, shdr_size)
        sh_text = cast(shdr_base + shdr_size, POINTER(Elf32_Shdr)).contents
        sh_text.sh_name = name_offsets[b'.text']
        sh_text.sh_type = SHT_PROGBITS
        sh_text.sh_flags = SHF_ALLOC | SHF_EXECINSTR
        sh_text.sh_addr = code_vaddr
        sh_text.sh_offset = code_file_offset
        sh_text.sh_size = code_size
        sh_text.sh_link = 0
        sh_text.sh_info = 0
        sh_text.sh_addralign = 16
        sh_text.sh_entsize = 0
        sh_cursor = shdr_base + 2 * shdr_size
        if data_present:
            sh_data = cast(sh_cursor, POINTER(Elf32_Shdr)).contents
            sh_data.sh_name = name_offsets[b'.data']
            sh_data.sh_type = SHT_PROGBITS
            sh_data.sh_flags = SHF_ALLOC | SHF_WRITE
            sh_data.sh_addr = data_vaddr
            sh_data.sh_offset = data_file_offset
            sh_data.sh_size = data_size
            sh_data.sh_link = 0
            sh_data.sh_info = 0
            sh_data.sh_addralign = 16
            sh_data.sh_entsize = 0
            sh_cursor += shdr_size
        sh_shstr = cast(sh_cursor, POINTER(Elf32_Shdr)).contents
        sh_shstr.sh_name = name_offsets[b'.shstrtab']
        sh_shstr.sh_type = SHT_STRTAB
        sh_shstr.sh_flags = 0
        sh_shstr.sh_addr = 0
        sh_shstr.sh_offset = shstrtab_offset
        sh_shstr.sh_size = len(shstrtab_bytes)
        sh_shstr.sh_link = 0
        sh_shstr.sh_info = 0
        sh_shstr.sh_addralign = 1
        sh_shstr.sh_entsize = 0
        self.out = e.raw
        return total_file_size

    def __gen_elf64(self):
        ehdr_size = sizeof(Elf64_Ehdr)
        phdr_size = sizeof(Elf64_Phdr)
        num_phdrs = 1
        shdr_size = sizeof(Elf64_Shdr)
        page_mask = PAGE_SIZE - 1
        pg_offset = self.start & page_mask
        segment_vaddr = self.start - pg_offset
        segment_offset = PAGE_SIZE
        # Layout inside segment
        code_file_offset = segment_offset + pg_offset
        code_vaddr = self.start
        code_size = self.code_size
        data_present = bool(self.data and self.data_size and self.data_size > 0)
        data_offset_in_segment = (pg_offset + code_size + (PAGE_SIZE - 1)) & ~page_mask if data_present else (pg_offset + code_size)
        data_file_offset = segment_offset + data_offset_in_segment
        data_vaddr = segment_vaddr + data_offset_in_segment
        data_size = self.data_size if data_present else 0
        segment_filesz = data_offset_in_segment + data_size
        segment_memsz = segment_filesz
        # Section names and shstrtab in first page
        sh_names = [b'', b'.text', b'.data'] if data_present else [b'', b'.text']
        sh_names.append(b'.shstrtab')
        shstrtab_bytes = b'\x00' + b'\x00'.join(name for name in sh_names[1:]) + b'\x00'
        name_offsets = {b'': 0}
        cur = 1
        for name in sh_names[1:]:
            name_offsets[name] = cur
            cur += len(name) + 1
        shnum = 1 + (2 if data_present else 1) + 1
        header_space_used = ehdr_size + (phdr_size * num_phdrs) + (shdr_size * shnum) + len(shstrtab_bytes)
        if header_space_used > PAGE_SIZE:
            raise ValueError("ELF headers+sections too large for a single page")
        shoff = ehdr_size + (phdr_size * num_phdrs)
        shstrtab_offset = shoff + (shdr_size * shnum)
        total_file_size = segment_offset + segment_filesz
        e = create_string_buffer(total_file_size)
        memset(e, 0, total_file_size)
        memset(addressof(e) + code_file_offset, TRAP, code_size)
        memmove(addressof(e) + shstrtab_offset, shstrtab_bytes, len(shstrtab_bytes))
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
        ehdr.e_shoff = shoff
        ehdr.e_flags = 0
        ehdr.e_ehsize = ehdr_size
        ehdr.e_phentsize = phdr_size
        ehdr.e_phnum = num_phdrs
        ehdr.e_shentsize = shdr_size
        ehdr.e_shnum = shnum
        ehdr.e_shstrndx = (2 if data_present else 1) + 1
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
            copy_size = min(len(self.code), code_size)
            memmove(addressof(e) + code_file_offset, self.code, copy_size)
        if data_present:
            if self.data:
                memmove(addressof(e) + data_file_offset, self.data, data_size)
            else:
                memset(addressof(e) + data_file_offset, 0, data_size)
        # Section headers
        shdr_base = addressof(e) + shoff
        sh_null = cast(shdr_base, POINTER(Elf64_Shdr)).contents
        memset(addressof(sh_null), 0, shdr_size)
        sh_text = cast(shdr_base + shdr_size, POINTER(Elf64_Shdr)).contents
        sh_text.sh_name = name_offsets[b'.text']
        sh_text.sh_type = SHT_PROGBITS
        sh_text.sh_flags = SHF_ALLOC | SHF_EXECINSTR
        sh_text.sh_addr = code_vaddr
        sh_text.sh_offset = code_file_offset
        sh_text.sh_size = code_size
        sh_text.sh_link = 0
        sh_text.sh_info = 0
        sh_text.sh_addralign = 16
        sh_text.sh_entsize = 0
        sh_cursor = shdr_base + 2 * shdr_size
        if data_present:
            sh_data = cast(sh_cursor, POINTER(Elf64_Shdr)).contents
            sh_data.sh_name = name_offsets[b'.data']
            sh_data.sh_type = SHT_PROGBITS
            sh_data.sh_flags = SHF_ALLOC | SHF_WRITE
            sh_data.sh_addr = data_vaddr
            sh_data.sh_offset = data_file_offset
            sh_data.sh_size = data_size
            sh_data.sh_link = 0
            sh_data.sh_info = 0
            sh_data.sh_addralign = 16
            sh_data.sh_entsize = 0
            sh_cursor += shdr_size
        sh_shstr = cast(sh_cursor, POINTER(Elf64_Shdr)).contents
        sh_shstr.sh_name = name_offsets[b'.shstrtab']
        sh_shstr.sh_type = SHT_STRTAB
        sh_shstr.sh_flags = 0
        sh_shstr.sh_addr = 0
        sh_shstr.sh_offset = shstrtab_offset
        sh_shstr.sh_size = len(shstrtab_bytes)
        sh_shstr.sh_link = 0
        sh_shstr.sh_info = 0
        sh_shstr.sh_addralign = 1
        sh_shstr.sh_entsize = 0
        self.out = e.raw
        return total_file_size
