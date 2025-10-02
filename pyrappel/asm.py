import logging
import keystone


class RappelKeystone:
    def __init__(self, arch):
        self.arch_name = arch
        self.ks = None
        if arch == 'x86':
            ks_arch = keystone.KS_ARCH_X86
            ks_mode = keystone.KS_MODE_32
        elif arch == 'x64':
            ks_arch = keystone.KS_ARCH_X86
            ks_mode = keystone.KS_MODE_64
        else:
            raise ValueError(f"Keystone unsupported architecture: {arch}")
        try:
            self.ks = keystone.Ks(ks_arch, ks_mode)
        except keystone.KsError as e:
            logging.error(f"[-] Failed to initialize Keystone for {arch}: {e}")
            raise

    def assemble(self, code: str, addr: int):
        if not self.ks:
            raise RuntimeError("Keystone assembler not initialized.")
        try:
            bytecode, count = self.ks.asm(code, addr, as_bytes=True)
            logging.info(f"[*] Assembled {count} instructions at 0x{addr:x}: {bytecode.hex()}")
            return bytecode, count
        except keystone.KsError as e:
            logging.error(f"[-] Keystone Error: {e}")
            logging.error(f"    Architecture: {self.arch_name}")
            logging.error(f"    Address: 0x{addr:x}")
            logging.error(f"    Code: '{code.strip()}'")
            return None, 0


