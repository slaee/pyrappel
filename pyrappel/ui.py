import os
import sys
import logging
import errno
import ctypes

from .config import settings, PAGE_SIZE, TRAP
from .asm import RappelKeystone
from .elf import ELF
from .exec_file import RappelExe
from .ptrace import Ptrace
from .arch import create_strategy

initial_data_buffer = ctypes.create_string_buffer(PAGE_SIZE)
ctypes.memset(initial_data_buffer, 0, PAGE_SIZE)

class Rappel:
    def __init__(self, arch='x64'):
        self.arch = arch
        self.__in_block = False
        self.exe_file_obj = None
        self.exe_fd = -1
        self.exe_path = None
        self.ptrace = None
        self.keystone = None
        self.child_pid = -1
        self.proc_info = None
        self.current_addr = settings['start_addr']
        try:
            self.keystone = RappelKeystone(self.arch)
            initial_code_buffer = ctypes.create_string_buffer(PAGE_SIZE)
            ctypes.memset(initial_code_buffer, TRAP, PAGE_SIZE)
            logging.info("[*] Generating minimal ELF executable...")
            elf = ELF(self.arch, code=initial_code_buffer.raw, code_size=PAGE_SIZE, data=initial_data_buffer.raw, data_size=PAGE_SIZE)
            elf.gen_elf()
            logging.info(f"[*] Writing executable to temporary file in '{settings['path']}'...")
            self.exe_file_obj = RappelExe.write(elf.out, path=None)
            if self.exe_file_obj is None:
                raise RuntimeError("Failed to write executable file.")
            self.exe_fd = self.exe_file_obj.fileno()
            self.exe_path = self.exe_file_obj.path
            logging.info(f"[*] Executable written to: {self.exe_path} (fd: {self.exe_fd})")
            self.ptrace = Ptrace(self.arch)
            self.proc_info = create_strategy(self.arch).create_proc_info()
            self.ptrace.init_proc_info(self.proc_info)
        except Exception as e:
            logging.error(f"[-] Initialization failed: {e}")
            self.cleanup()
            sys.exit(1)

    def __trace_child(self):
        try:
            pid = os.fork()
            if pid == 0:
                self.ptrace.child(self.exe_fd, self.exe_path)
                os._exit(1)
            elif pid > 0:
                logging.info(f"[+] Child process started (pid={pid}).")
                return pid
            else:
                raise OSError("Failed to fork")
        except Exception as e:
            logging.error(f"[-] Error forking/execing child: {e}")
            return -1

    def display_info(self):
        if not self.proc_info:
            return
        try:
            strategy = create_strategy(self.arch)
            strategy.reg_info(self.proc_info)
        except Exception as e:
            print(f"[!] Error displaying register info: {e}")

    def interact(self):
        try:
            self.child_pid = self.__trace_child()
            if self.child_pid < 0:
                raise RuntimeError("Failed to start child process.")
            if not self.ptrace.launch(self.child_pid):
                raise RuntimeError("Failed initial ptrace setup with child.")
            logging.info("[*] Continuing child to first instruction...")
            self.ptrace.cont(self.child_pid)
            if self.ptrace.reap(self.child_pid, self.proc_info) == 1:
                logging.error("[-] Child exited unexpectedly during initial run.")
                self.display_info()
                return
            logging.info("[*] Child stopped at entry point. Initial state:")
            self.display_info()
            if self.arch == 'x64':
                self.current_addr = self.proc_info.regs_struct.rip
            else:
                self.current_addr = self.proc_info.regs_struct.eip
            logging.info(f"[*] Current address: {self.current_addr:#x}")
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
                    bytecode, count = self.keystone.assemble(line, self.current_addr)
                    if bytecode is None or count == 0:
                        continue
                    instruction_size = len(bytecode)
                    if not self.ptrace.write(self.child_pid, self.current_addr, bytecode):
                        logging.error("[-] Failed to write instruction to memory. Aborting.")
                        break
                    self.ptrace.cont(self.child_pid)
                    exit_status = self.ptrace.reap(self.child_pid, self.proc_info)
                    self.display_info()
                    if exit_status == 1:
                        logging.info("[*] Process finished.")
                        break
                    if self.arch == 'x64':
                        expected_next_addr = self.current_addr + instruction_size + 1
                        actual_next_addr = self.proc_info.regs_struct.rip
                        if actual_next_addr != expected_next_addr:
                            logging.warning(f"[!] Warning: RIP is {actual_next_addr:#x}, expected {expected_next_addr:#x}. Control flow changed?")
                        self.current_addr = actual_next_addr
                    else:
                        # On x86, after hitting INT3 the kernel reports EIP at the trap address
                        # (not after it). So the expected next address does not add +1.
                        expected_next_addr = self.current_addr + instruction_size
                        actual_next_addr = self.proc_info.regs_struct.eip
                        if actual_next_addr != expected_next_addr:
                            logging.warning(f"[!] Warning: EIP is {actual_next_addr:#x}, expected {expected_next_addr:#x}. Control flow changed?")
                        self.current_addr = actual_next_addr
                except EOFError:
                    logging.error("[-] EOF received, quitting.")
                    break
                except KeyboardInterrupt:
                    logging.error("[-] Keyboard interrupt received, quitting.")
                    break
                except Exception as loop_e:
                    logging.error(f"[-] Error during interaction loop: {loop_e}")
                    break
        finally:
            self.cleanup()

    def __prompt(self):
        prompt_addr = f"{self.current_addr:#x}"
        if self.__in_block:
            print(f"{prompt_addr}... ", end="")
        else:
            print(f"{prompt_addr}> ", end="")
        sys.stdout.flush()
        return input()

    def cleanup(self):
        logging.info("[*] Cleaning up...")
        if self.child_pid > 0:
            try:
                os.kill(self.child_pid, 0)
                logging.info(f"[*] Detaching from child process {self.child_pid}...")
                self.ptrace.detach(self.child_pid)
            except ProcessLookupError:
                logging.info(f"[*] Child process {self.child_pid} already exited.")
            except OSError as e:
                if e.errno != errno.ESRCH:  # type: ignore[name-defined]
                    logging.error(f"[-] Error detaching/killing child process {self.child_pid}: {e}")
            except Exception as e:
                logging.error(f"[-] Unexpected error during child cleanup: {e}")
            self.child_pid = -1
        if self.exe_file_obj is not None:
            RappelExe.cleanup(self.exe_file_obj)
            self.exe_file_obj = None
            self.exe_fd = -1
            self.exe_path = None
        elif self.exe_path and os.path.exists(self.exe_path):
            try:
                os.unlink(self.exe_path)
                logging.info(f"[*] Cleaned up executable file: {self.exe_path}")
            except OSError as e:
                logging.warning(f"[!] Failed to cleanup executable '{self.exe_path}': {e}")
        logging.info("[*] Cleanup finished.")


