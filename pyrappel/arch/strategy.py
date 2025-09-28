from ctypes import Structure, c_uint32, c_uint16, c_uint8, c_ulonglong, c_uint64, c_long, c_int, sizeof, cast, POINTER, addressof
from dataclasses import dataclass
from ..types import IOVec
from ..config import settings
from ..utils import print_bit, REGFMT16, REGFMT32, REGFMT64, RED, RST


class ArchStrategy:
    def create_proc_info(self):
        raise NotImplementedError

    def get_word_size(self):
        raise NotImplementedError

    def get_pack_fmt(self):
        raise NotImplementedError

    def reg_info(self, info):
        raise NotImplementedError


# 32-bit structures
class user_regs_struct_x86(Structure):
    _fields_ = [
        ('ebx', c_uint32), ('ecx', c_uint32), ('edx', c_uint32),
        ('esi', c_uint32), ('edi', c_uint32), ('ebp', c_uint32),
        ('eax', c_uint32), ('xds', c_uint32), ('xes', c_uint32),
        ('xfs', c_uint32), ('xgs', c_uint32), ('orig_eax', c_uint32),
        ('eip', c_uint32), ('xcs', c_uint32), ('eflags', c_uint32),
        ('esp', c_uint32), ('xss', c_uint32)
    ]

class user_fpregs_struct_x86(Structure):
    _fields_ = [
        ('cwd', c_uint32), ('swd', c_uint32), ('twd', c_uint32),
        ('fip', c_uint32), ('fcs', c_uint32), ('foo', c_uint32),
        ('fos', c_uint32), ('st_space', c_uint32 * 20)
    ]

class user_fpxregs_struct_x86(Structure):
    _pack_ = 16
    _fields_ = [
        ('cwd', c_uint16), ('swd', c_uint16), ('twd', c_uint16), ('fop', c_uint16),
        ('fip', c_uint32), ('fcs', c_uint32), ('foo', c_uint32), ('fos', c_uint32),
        ('mxcsr', c_uint32), ('mxcsr_mask', c_uint32),
        ('st_space', c_uint8 * 128), ('xmm_space', c_uint8 * 128),
        ('padding', c_uint8 * 96)
    ]


# 64-bit structures
class user_regs_struct_x64(Structure):
    _fields_ = [
        ('r15', c_ulonglong), ('r14', c_ulonglong), ('r13', c_ulonglong), ('r12', c_ulonglong),
        ('rbp', c_ulonglong), ('rbx', c_ulonglong), ('r11', c_ulonglong), ('r10', c_ulonglong),
        ('r9', c_ulonglong), ('r8', c_ulonglong), ('rax', c_ulonglong), ('rcx', c_ulonglong),
        ('rdx', c_ulonglong), ('rsi', c_ulonglong), ('rdi', c_ulonglong), ('orig_rax', c_ulonglong),
        ('rip', c_ulonglong), ('cs', c_ulonglong), ('eflags', c_ulonglong), ('rsp', c_ulonglong),
        ('ss', c_ulonglong), ('fs_base', c_ulonglong), ('gs_base', c_ulonglong),
        ('ds', c_ulonglong), ('es', c_ulonglong), ('fs', c_ulonglong), ('gs', c_ulonglong)
    ]

class user_fpregs_struct_x64(Structure):
    _pack_ = 16
    _fields_ = [
        ('cwd', c_uint16), ('swd', c_uint16), ('ftw', c_uint16), ('fop', c_uint16),
        ('rip', c_uint64), ('rdp', c_uint64), ('mxcsr', c_uint32), ('mxcsr_mask', c_uint32),
        ('st_space', c_uint8 * 128), ('xmm_space', c_uint8 * 256), ('padding', c_uint8 * 96)
    ]


# ProcInfo containers
class ProcInfoX86:
    def __init__(self):
        self.pid = c_long(0)
        self.regs_struct = user_regs_struct_x86()
        self.old_regs_struct = user_regs_struct_x86()
        self.regs = IOVec()

        self.fpregs_struct = user_fpregs_struct_x86()
        self.old_fpregs_struct = user_fpregs_struct_x86()
        self.fpregs = IOVec()

        self.fpxregs_struct = user_fpxregs_struct_x86()
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

        self.fpregs_struct = user_fpregs_struct_x64()
        self.old_fpregs_struct = user_fpregs_struct_x64()
        self.fpregs = IOVec()

        self.sig = c_int(-1)
        self.exit_code = c_int(-1)


class X86Strategy(ArchStrategy):
    def create_proc_info(self):
        return ProcInfoX86()

    def get_word_size(self):
        return 4

    def get_pack_fmt(self):
        return '<I'

    def reg_info(self, info):
        regs = info.regs_struct
        old = info.old_regs_struct
        print("-" * 80)
        def p32(name):
            v = getattr(regs, name); o = getattr(old, name)
            print((REGFMT32.format(v) if v == o else f"{RED}{REGFMT32.format(v)}{RST}"), end="")
        def p16(name):
            v = getattr(regs, name); o = getattr(old, name)
            print((REGFMT16.format(v) if v == o else f"{RED}{REGFMT16.format(v)}{RST}"), end="")
        print("eax=", end=""); p32("eax"); print(" ", end="")
        print("ebx=", end=""); p32("ebx"); print(" ", end="")
        print("ecx=", end=""); p32("ecx"); print("\n", end="")
        print("edx=", end=""); p32("edx"); print(" ", end="")
        print("esi=", end=""); p32("esi"); print(" ", end="")
        print("edi=", end=""); p32("edi"); print("\n", end="")
        print("eip=", end=""); p32("eip"); print(" ", end="")
        print("esp=", end=""); p32("esp"); print(" ", end="")
        print("ebp=", end=""); p32("ebp"); print(" ", end="")
        e = regs.eflags; oe = old.eflags
        cf, pf, af, zf, sf, df, of = (e & 1), (e >> 2) & 1, (e >> 4) & 1, (e >> 6) & 1, (e >> 7) & 1, (e >> 10) & 1, (e >> 11) & 1
        ocf, opf, oaf, ozf, osf, odf, oof = (oe & 1), (oe >> 2) & 1, (oe >> 4) & 1, (oe >> 6) & 1, (oe >> 7) & 1, (oe >> 10) & 1, (oe >> 11) & 1
        print("\nFlags=[", end=""); print_bit("CF:", cf, ocf, " "); print_bit("PF:", pf, opf, " "); print_bit("AF:", af, oaf, " "); print_bit("ZF:", zf, ozf, " "); print_bit("SF:", sf, osf, " "); print_bit("DF:", df, odf, " "); print_bit("OF:", of, oof, "] ")
        print("eflags=", end=""); p32("eflags"); print("\n", end="")
        print("cs=", end=""); p16("xcs"); print(" ", end="")
        print("ss=", end=""); p16("xss"); print(" ", end="")
        print("ds=", end=""); p16("xds"); print(" ", end="")
        print("es=", end=""); p16("xes"); print(" ", end="")
        print("fs=", end=""); p16("xfs"); print(" ", end="")
        print("gs=", end=""); p16("xgs"); print("\n", end="")
        if settings.get('all_regs') == True:
            fpregs = info.fpregs_struct
            old_fpregs = info.old_fpregs_struct
            fpxregs = info.fpxregs_struct
            old_fpxregs = info.old_fpxregs_struct
            # FSAVE state
            if getattr(info.fpregs, 'iov_len', 0) >= sizeof(user_fpregs_struct_x86):
                print("\n--- FPU Registers (FSAVE state) ---")
                for name in ["cwd","swd","twd","fip","fcs","foo","fos"]:
                    print(f"{name}=", end="");
                    v = getattr(fpregs, name); o = getattr(old_fpregs, name)
                    print((REGFMT32.format(v) if v == o else f"{RED}{REGFMT32.format(v)}{RST}"), end=" ")
                print("\nST Registers (raw longs):")
                for i in range(8):
                    print(f" ST{i}: ", end="")
                    base = i * (10 // sizeof(c_long))
                    for j in range(10 // sizeof(c_long)):
                        idx = base + j
                        if idx < len(fpregs.st_space):
                            y = fpregs.st_space[idx]; z = old_fpregs.st_space[idx]
                            print((REGFMT32.format(y) if y == z else f"{RED}{REGFMT32.format(y)}{RST}"), end=" ")
                    print()
            else:
                print("\n--- FPU Registers (FSAVE state): Not Available ---")
            # FXSAVE state
            if getattr(info.fpxregs, 'iov_len', 0) >= sizeof(user_fpxregs_struct_x86):
                print("\n--- Extended FPU/MMX/SSE Registers (FXSAVE state) ---")
                for name in ["cwd","swd","twd","fop","fip","fcs","foo","fos","mxcsr","mxcsr_mask"]:
                    print(f"{name}=", end="")
                    v = getattr(fpxregs, name); o = getattr(old_fpxregs, name)
                    fmt = REGFMT16 if name in ["cwd","swd","twd","fop"] else REGFMT32
                    print((fmt.format(v) if v == o else f"{RED}{fmt.format(v)}{RST}"), end=" ")
                print("\nST/MMX Registers (fxsave layout):")
                st_fx_bytes = cast(fpxregs.st_space, POINTER(c_uint8 * 128)).contents
                old_st_fx_bytes = cast(old_fpxregs.st_space, POINTER(c_uint8 * 128)).contents
                for i in range(8):
                    print(f" ST{i}/MM{i}: ", end="")
                    for j in range(16):
                        idx = i * 16 + j
                        b, ob = st_fx_bytes[idx], old_st_fx_bytes[idx]
                        print((f"{b:02x}" if b == ob else f"{RED}{b:02x}{RST}"), end="")
                        if j % 4 == 3: print(" ", end="")
                    print()
                print("XMM Registers (0-7):")
                xmm_bytes = cast(fpxregs.xmm_space, POINTER(c_uint8 * 128)).contents
                old_xmm_bytes = cast(old_fpxregs.xmm_space, POINTER(c_uint8 * 128)).contents
                for i in range(8):
                    print(f" XMM{i}: ", end="")
                    for j in range(16):
                        idx = i * 16 + j
                        b, ob = xmm_bytes[idx], old_xmm_bytes[idx]
                        print((f"{b:02x}" if b == ob else f"{RED}{b:02x}{RST}"), end="")
                        if j == 7: print(" ", end="")
                    print()
            else:
                print("\n--- Extended FPU/MMX/SSE Registers (FXSAVE state): Not Available ---")
        print("-" * 80)


class X64Strategy(ArchStrategy):
    def create_proc_info(self):
        return ProcInfoX64()

    def get_word_size(self):
        return 8

    def get_pack_fmt(self):
        return '<Q'

    def reg_info(self, info):
        regs = info.regs_struct
        old = info.old_regs_struct
        print("-" * 80)
        def p64(name):
            v = getattr(regs, name); o = getattr(old, name)
            print((REGFMT64.format(v) if v == o else f"{RED}{REGFMT64.format(v)}{RST}"), end="")
        def p16(name):
            v = getattr(regs, name); o = getattr(old, name)
            print((REGFMT16.format(v) if v == o else f"{RED}{REGFMT16.format(v)}{RST}"), end="")
        print("rax=", end=""); p64("rax"); print(" ", end="")
        print("rbx=", end=""); p64("rbx"); print(" ", end="")
        print("rcx=", end=""); p64("rcx"); print("\n", end="")
        print("rdx=", end=""); p64("rdx"); print(" ", end="")
        print("rsi=", end=""); p64("rsi"); print(" ", end="")
        print("rdi=", end=""); p64("rdi"); print("\n", end="")
        print("rip=", end=""); p64("rip"); print(" ", end="")
        print("rsp=", end=""); p64("rsp"); print(" ", end="")
        print("rbp=", end=""); p64("rbp"); print("\n", end="")
        print(" r8=", end=""); p64("r8"); print(" ", end="")
        print(" r9=", end=""); p64("r9"); print(" ", end="")
        print("r10=", end=""); p64("r10"); print("\n", end="")
        print("r11=", end=""); p64("r11"); print(" ", end="")
        print("r12=", end=""); p64("r12"); print(" ", end="")
        print("r13=", end=""); p64("r13"); print("\n", end="")
        print("r14=", end=""); p64("r14"); print(" ", end="")
        print("r15=", end=""); p64("r15"); print("\n", end="")
        e = regs.eflags; oe = old.eflags
        cf, pf, af, zf, sf, df, of = (e & 1), (e >> 2) & 1, (e >> 4) & 1, (e >> 6) & 1, (e >> 7) & 1, (e >> 10) & 1, (e >> 11) & 1
        ocf, opf, oaf, ozf, osf, odf, oof = (oe & 1), (oe >> 2) & 1, (oe >> 4) & 1, (oe >> 6) & 1, (oe >> 7) & 1, (oe >> 10) & 1, (oe >> 11) & 1
        print("\nFlags=[", end=""); print_bit("CF:", cf, ocf, " "); print_bit("PF:", pf, opf, " "); print_bit("AF:", af, oaf, " "); print_bit("ZF:", zf, ozf, " "); print_bit("SF:", sf, osf, " "); print_bit("DF:", df, odf, " "); print_bit("OF:", of, oof, "] ")
        print("rflags=", end=""); p64("eflags"); print("\n", end="")
        print("cs=", end=""); p16("cs"); print(" ", end="")
        print("ss=", end=""); p16("ss"); print(" ", end="")
        print("ds=", end=""); p16("ds"); print(" ", end="")
        print("es=", end=""); p16("es"); print(" ", end="")
        print("fs=", end=""); p16("fs"); print(" ", end="")
        print("gs=", end=""); p16("gs"); print("\n", end="")
        print("fs_base=", end=""); p64("fs_base"); print(" ", end="")
        print("gs_base=", end=""); p64("gs_base"); print("\n", end="")
        if settings.get('all_regs') == True:
            fpregs = info.fpregs_struct
            old_fpregs = info.old_fpregs_struct
            if getattr(info.fpregs, 'iov_len', 0) >= sizeof(user_fpregs_struct_x64):
                print("\n--- FPU/MMX/SSE Registers (FXSAVE state) ---")
                for name in ["cwd","swd","ftw","fop"]:
                    print(f"{name}=", end="");
                    v = getattr(fpregs, name); o = getattr(old_fpregs, name)
                    print((REGFMT16.format(v) if v == o else f"{RED}{REGFMT16.format(v)}{RST}"), end=" ")
                for name in ["rip","rdp"]:
                    print(f"{name}=", end="");
                    v = getattr(fpregs, name); o = getattr(old_fpregs, name)
                    print((REGFMT64.format(v) if v == o else f"{RED}{REGFMT64.format(v)}{RST}"), end=" ")
                for name in ["mxcsr","mxcsr_mask"]:
                    print(f"{name}=", end="");
                    v = getattr(fpregs, name); o = getattr(old_fpregs, name)
                    print((REGFMT32.format(v) if v == o else f"{RED}{REGFMT32.format(v)}{RST}"), end=" ")
                print("\nST/MMX Registers (fxsave layout):")
                st_fx_bytes = cast(fpregs.st_space, POINTER(c_uint8 * 128)).contents
                old_st_fx_bytes = cast(old_fpregs.st_space, POINTER(c_uint8 * 128)).contents
                for i in range(8):
                    print(f" ST{i}/MM{i}: ", end="")
                    for j in range(16):
                        idx = i * 16 + j
                        b, ob = st_fx_bytes[idx], old_st_fx_bytes[idx]
                        print((f"{b:02x}" if b == ob else f"{RED}{b:02x}{RST}"), end="")
                        if j % 4 == 3: print(" ", end="")
                    print()
                print("XMM Registers (0-15):")
                xmm_bytes = cast(fpregs.xmm_space, POINTER(c_uint8 * 256)).contents
                old_xmm_bytes = cast(old_fpregs.xmm_space, POINTER(c_uint8 * 256)).contents
                for i in range(16):
                    print(f" XMM{i:<3}: ", end="")
                    for j in range(16):
                        idx = i * 16 + j
                        b, ob = xmm_bytes[idx], old_xmm_bytes[idx]
                        print((f"{b:02x}" if b == ob else f"{RED}{b:02x}{RST}"), end="")
                        if j == 7: print(" ", end="")
                    print()
            else:
                print("\n--- FPU/MMX/SSE Registers (FXSAVE state): Not Available ---")
        print("-" * 80)


def create_strategy(arch: str) -> ArchStrategy:
    if arch == 'x86':
        return X86Strategy()
    if arch == 'x64':
        return X64Strategy()
    raise ValueError(f"Unsupported architecture: {arch}")


