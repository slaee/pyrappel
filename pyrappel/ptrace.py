import os
import sys
import errno
import struct
import ctypes
import ctypes.util
import logging
import signal
from ctypes import cdll, c_int, c_void_p, c_long, POINTER, c_ulong, set_errno, get_errno, byref, pointer, sizeof, addressof


libc_path = ctypes.util.find_library('c')
if not libc_path:
    raise ImportError("Could not find libc library.")
try:
    libc = cdll.LoadLibrary(libc_path)
except OSError as e:
    logging.error(f"[-] Failed to load libc from {libc_path}: {e}")
    sys.exit(1)

try:
    libc.ptrace.argtypes = [c_int, c_int, c_void_p, c_void_p]
    libc.ptrace.restype = c_long
    libc.waitpid.argtypes = [c_int, POINTER(c_int), c_int]
    libc.waitpid.restype = c_int
except AttributeError as e:
    logging.error(f"[-] Error setting up ctypes for libc functions: {e}")
    sys.exit(1)


PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2
PTRACE_POKETEXT = 4
PTRACE_POKEDATA = 5
PTRACE_CONT = 7
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_GETFPREGS = 14
PTRACE_SETFPREGS = 15
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_GETFPXREGS = 18
PTRACE_SETFPXREGS = 19
PTRACE_SYSCALL = 24

PTRACE_KILL = 31

PTRACE_SETOPTIONS = 0x4200
PTRACE_GETEVENTMSG = 0x4201
PTRACE_GETSIGINFO = 0x4202
PTRACE_SETSIGINFO = 0x4203
PTRACE_GETREGSET = 0x4204
PTRACE_SETREGSET = 0x4205

PTRACE_O_TRACESYSGOOD = 1
PTRACE_O_TRACEFORK = (1 << 1)
PTRACE_O_TRACEVFORK = (1 << 2)
PTRACE_O_TRACECLONE = (1 << 3)
PTRACE_O_TRACEEXEC = (1 << 4)
PTRACE_O_TRACEVFORKDONE = (1 << 5)
PTRACE_O_TRACEEXIT = (1 << 6)
PTRACE_O_EXITKILL = (1 << 20)

PTRACE_EVENT_FORK = 1
PTRACE_EVENT_VFORK = 2
PTRACE_EVENT_CLONE = 3
PTRACE_EVENT_EXEC = 4
PTRACE_EVENT_VFORK_DONE = 5
PTRACE_EVENT_EXIT = 6
PTRACE_EVENT_SECCOMP = 7
PTRACE_EVENT_STOP = 128

NT_PRSTATUS = 1
NT_PRFPREG = 2
NT_PRPSINFO = 3
NT_TASKSTRUCT = 4
NT_AUXV = 6
NT_X86_XSTATE = 0x202


class Ptrace:
    def __init__(self, arch):
        self.arch = arch
        # Set sizes based on tracee architecture, not host
        self.word_size = 8 if arch == 'x64' else 4
        self.word_mask = (1 << (self.word_size * 8)) - 1
        self.pack_fmt = '<Q' if self.word_size == 8 else '<I'

    def _ptrace_call(self, request, pid, addr, data):
        ctypes.set_errno(0)
        addr_arg = c_void_p(addr) if isinstance(addr, int) else addr
        if request in (PTRACE_POKEDATA, PTRACE_POKETEXT):
            data_arg = data
        elif request in (PTRACE_GETREGSET, PTRACE_SETREGSET, PTRACE_GETSIGINFO, PTRACE_SETSIGINFO, PTRACE_GETEVENTMSG):
            data_arg = data
        elif request in (PTRACE_PEEKDATA, PTRACE_PEEKTEXT):
            data_arg = c_void_p(data)
        elif request in (PTRACE_CONT, PTRACE_SYSCALL, PTRACE_DETACH, PTRACE_SINGLESTEP, PTRACE_KILL, PTRACE_SETOPTIONS):
            data_arg = data
        elif request == PTRACE_TRACEME:
            addr_arg = c_void_p(0)
            data_arg = c_void_p(0)
        else:
            data_arg = c_void_p(data) if not isinstance(data, ctypes._Pointer) else data
        result = libc.ptrace(request, pid, addr_arg, data_arg)
        err = ctypes.get_errno()
        if request in (PTRACE_PEEKTEXT, PTRACE_PEEKDATA):
            if result == -1 and err != 0:
                raise OSError(err, f"ptrace({request}, pid={pid}, addr={addr:#x}) failed: {os.strerror(err)}")
            return result
        elif result == -1:
            if err == errno.ESRCH and request in (PTRACE_CONT, PTRACE_DETACH, PTRACE_KILL, PTRACE_GETREGSET, PTRACE_SETREGSET, PTRACE_GETSIGINFO, PTRACE_SETSIGINFO, PTRACE_GETEVENTMSG):
                return result
            raise OSError(err, f"ptrace({request}, pid={pid}, addr={addr}, data={data}) failed: {os.strerror(err)}")
        return result

    def child(self, exe_fd, exe_path):
        try:
            self._ptrace_call(PTRACE_TRACEME, 0, None, None)
            program_name = os.path.basename(exe_path).encode('utf-8')
            py_argv = [program_name]
            py_env = os.environ
            os.execve(exe_path, py_argv, py_env)
            err = ctypes.get_errno()
            logging.error(f"[-] Child: execve failed for '{exe_path}': {os.strerror(err)}")
            os._exit(1)
        except Exception as e:
            logging.error(f"[-] Child process error during PTRACE_TRACEME or execve preparation: {e}")
            os._exit(1)

    def launch(self, pid):
        try:
            status = c_int(0)
            ret = libc.waitpid(pid, byref(status), 0)
            if ret < 0:
                err = ctypes.get_errno()
                raise OSError(err, f"waitpid failed for initial trap (pid={pid}): {os.strerror(err)}")
            if not os.WIFSTOPPED(status.value) or os.WSTOPSIG(status.value) != signal.SIGTRAP:
                print(f"[!] Expected SIGTRAP after execve, but got status {status.value:#x}")
                return False
            logging.info(f"[*] Child process (pid={pid}) stopped with SIGTRAP (initial).")
            options = PTRACE_O_TRACEEXIT
            self._ptrace_call(PTRACE_SETOPTIONS, pid, None, options)
            logging.info(f"[*] Set PTRACE_O_TRACEEXIT option for pid={pid}.")
            return True
        except OSError as e:
            logging.error(f"[-] Error launching/waiting for process {pid}: {e}")
            return False
        except Exception as e:
            logging.error(f"[-] Unexpected error during launch: {e}")
            return False

    def cont(self, pid):
        try:
            self._ptrace_call(PTRACE_CONT, pid, None, 0)
        except OSError as e:
            if e.errno != errno.ESRCH:
                logging.error(f"[-] Error continuing process {pid}: {e}")
                raise

    def detach(self, pid):
        try:
            self._ptrace_call(PTRACE_DETACH, pid, None, 0)
            logging.info(f"[*] Detached from process {pid}")
        except OSError as e:
            if e.errno != errno.ESRCH:
                logging.error(f"[-] Error detaching from process {pid}: {e}")

    def reap(self, pid, info):
        try:
            status = c_int(0)
            ret = libc.waitpid(pid, byref(status), 0)
            if ret < 0:
                err = ctypes.get_errno()
                if err == errno.ECHILD:
                    logging.info(f"[*] waitpid({pid}): No such child process (already reaped or detached?). Assuming exited.")
                    info.sig.value = 0
                    info.exit_code.value = 0
                    return 1
                raise OSError(err, f"waitpid failed for pid={pid}: {os.strerror(err)}")
            info.sig.value = -1
            info.exit_code.value = -1
            if os.WIFEXITED(status.value):
                exit_code = os.WEXITSTATUS(status.value)
                logging.info(f"[+] Process {pid} exited normally with code {exit_code}.")
                info.exit_code.value = exit_code
                info.sig.value = 0
                return 1
            if os.WIFSIGNALED(status.value):
                term_sig = os.WTERMSIG(status.value)
                try:
                    sig_name = signal.Signals(term_sig).name
                except ValueError:
                    sig_name = "Unknown"
                logging.error(f"[-] Process {pid} terminated by signal {term_sig} ({sig_name}).")
                info.sig.value = term_sig
                return 1
            if os.WIFSTOPPED(status.value):
                stop_sig = os.WSTOPSIG(status.value)
                if stop_sig == signal.SIGTRAP and (status.value >> 8) > 0:
                    event = status.value >> 16
                    if event == PTRACE_EVENT_EXIT:
                        logging.info(f"[*] Process {pid} stopped with PTRACE_EVENT_EXIT.")
                        exit_code_ptr = pointer(c_ulong(0))
                        try:
                            self._ptrace_call(PTRACE_GETEVENTMSG, pid, None, exit_code_ptr)
                            info.exit_code.value = exit_code_ptr.contents.value
                            logging.info(f"[+] Exit code reported: {info.exit_code.value}")
                        except OSError as e:
                            logging.error(f"[-] Failed to get exit code via PTRACE_GETEVENTMSG: {e}")
                            info.exit_code.value = -1
                        self._collect_regs(pid, info)
                        info.sig.value = 0
                        return 1
                    else:
                        logging.info(f"[*] Process {pid} stopped with SIGTRAP and event {event:#x}.")
                        self._collect_regs(pid, info)
                        info.sig.value = stop_sig
                        return 0
                try:
                    sig_name = signal.Signals(stop_sig).name
                except ValueError:
                    sig_name = "Unknown"
                if stop_sig != signal.SIGTRAP:
                    logging.info(f"[*] Process {pid} stopped by signal {stop_sig} ({sig_name}).")
                self._collect_regs(pid, info)
                info.sig.value = stop_sig
                return 0
            print(f"[!] Unknown wait status for pid={pid}: {status.value:#x}")
            return 1
        except OSError as e:
            if e.errno == errno.ESRCH:
                logging.info(f"[*] reap({pid}): Process already exited (ESRCH).")
                info.sig.value = 0
                info.exit_code.value = 0
                return 1
            logging.error(f"[-] Error reaping process {pid}: {e}")
            return 1
        except Exception as e:
            logging.error(f"[-] Unexpected error during reap: {e}")
            return 1

    def read(self, pid, base_address, size):
        data = bytearray(size)
        addr = base_address
        bytes_read = 0
        try:
            while bytes_read < size:
                aligned_addr = addr & ~(self.word_size - 1)
                addr_offset = addr - aligned_addr
                word_val_signed = self._ptrace_call(PTRACE_PEEKDATA, pid, aligned_addr, None)
                word_val_unsigned = word_val_signed & self.word_mask
                word_bytes = struct.pack(self.pack_fmt, word_val_unsigned)
                bytes_to_copy = min(self.word_size - addr_offset, size - bytes_read)
                data[bytes_read : bytes_read + bytes_to_copy] = word_bytes[addr_offset : addr_offset + bytes_to_copy]
                bytes_read += bytes_to_copy
                addr += bytes_to_copy
            return bytes(data)
        except OSError as e:
            logging.error(f"[-] Error reading memory from pid={pid} at {base_address:#x} (size={size}): {e}")
            return None

    def write(self, pid, base_address, data):
        size = len(data)
        addr = base_address
        bytes_written = 0
        try:
            while bytes_written < size:
                aligned_addr = addr & ~(self.word_size - 1)
                addr_offset = addr - aligned_addr
                bytes_to_write_this_word = min(self.word_size - addr_offset, size - bytes_written)
                if addr_offset != 0 or bytes_to_write_this_word != self.word_size:
                    original_word_val_signed = self._ptrace_call(PTRACE_PEEKDATA, pid, aligned_addr, None)
                    original_word_val_unsigned = original_word_val_signed & self.word_mask
                    original_word_bytes = bytearray(struct.pack(self.pack_fmt, original_word_val_unsigned))
                else:
                    original_word_bytes = bytearray(self.word_size)
                new_data_chunk = data[bytes_written : bytes_written + bytes_to_write_this_word]
                original_word_bytes[addr_offset : addr_offset + bytes_to_write_this_word] = new_data_chunk
                modified_word_val_unsigned = struct.unpack(self.pack_fmt, original_word_bytes)[0]
                self._ptrace_call(PTRACE_POKEDATA, pid, aligned_addr, modified_word_val_unsigned)
                bytes_written += bytes_to_write_this_word
                addr += bytes_to_write_this_word
            return True
        except OSError as e:
            logging.error(f"[-] Error writing memory to pid={pid} at {base_address:#x} (size={size}): {e}")
            return False

    def init_proc_info(self, info):
        info.regs.iov_base = addressof(info.regs_struct)
        if self.arch == 'x86':
            info.regs.iov_len = sizeof(type(info.regs_struct))
            info.fpregs.iov_base = addressof(info.fpregs_struct)
            info.fpregs.iov_len = sizeof(type(info.fpregs_struct))
            info.fpxregs.iov_base = addressof(info.fpxregs_struct)
            info.fpxregs.iov_len = sizeof(type(info.fpxregs_struct))
        else:
            info.regs.iov_len = sizeof(type(info.regs_struct))
            info.fpregs.iov_base = addressof(info.fpregs_struct)
            info.fpregs.iov_len = sizeof(type(info.fpregs_struct))

    def _collect_regs(self, pid, info):
        # Preserve old GP regs
        info.old_regs_struct = type(info.regs_struct).from_buffer_copy(info.regs_struct)
        try:
            self._ptrace_call(PTRACE_GETREGSET, pid, NT_PRSTATUS, byref(info.regs))
        except OSError as e:
            logging.error(f"[-] Failed to get GPRs (NT_PRSTATUS) for pid={pid}: {e}")
            raise
        # Preserve old FP regs if available before refresh
        if hasattr(info, 'fpregs') and getattr(info.fpregs, 'iov_len', 0) > 0:
            try:
                info.old_fpregs_struct = type(info.fpregs_struct).from_buffer_copy(info.fpregs_struct)
            except Exception:
                pass
        if hasattr(info, 'fpregs'):
            try:
                self._ptrace_call(PTRACE_GETREGSET, pid, NT_PRFPREG, byref(info.fpregs))
            except OSError:
                info.fpregs.iov_len = 0
        # Preserve old FXSAVE regs on x86 before refresh
        if self.arch == 'x86' and hasattr(info, 'fpxregs') and getattr(info.fpxregs, 'iov_len', 0) > 0:
            try:
                info.old_fpxregs_struct = type(info.fpxregs_struct).from_buffer_copy(info.fpxregs_struct)
            except Exception:
                pass
        if self.arch == 'x86' and hasattr(info, 'fpxregs'):
            try:
                NT_PRXFPREG = 0x46e62b7f
                info.fpxregs.iov_len = sizeof(type(info.fpxregs_struct))
                self._ptrace_call(PTRACE_GETREGSET, pid, NT_PRXFPREG, byref(info.fpxregs))
            except OSError:
                info.fpxregs.iov_len = 0


