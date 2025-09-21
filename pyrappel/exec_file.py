import ctypes
import errno
import logging
import os
import stat
import tempfile

from .config import settings


class ExecutableFile:
    def __init__(self, fd, path, is_temp):
        if not isinstance(fd, int) or fd < 0:
            raise ValueError("Invalid file descriptor provided.")
        self._fd = fd
        self.path = path
        self.is_temp = is_temp

    def fileno(self):
        if self._fd < 0:
            raise ValueError("File descriptor is closed or invalid.")
        return self._fd

    def close(self):
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError as e:
                logging.error(f"[-] Warning: Failed to close fd {self._fd} for {self.path}: {e}")
            finally:
                self._fd = -1

    def __del__(self):
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1

    @property
    def temp_path(self):
        return self.path if self.is_temp else None


class RappelExe:
    @staticmethod
    def write(data, path=None) -> ExecutableFile | None:
        is_temp = False
        file_path = path
        fd = -1
        ro_fd = -1

        try:
            if path is None:
                is_temp = True
                temp_dir = settings.get('path', '/tmp')
                if not os.path.isdir(temp_dir):
                    os.makedirs(temp_dir, exist_ok=True)
                fd, file_path = tempfile.mkstemp(prefix='rappel-exe.', dir=temp_dir)
                if fd < 0:
                    raise OSError(f"Failed to create temporary file: {os.strerror(ctypes.get_errno())}")
                try:
                    bytes_written = os.write(fd, data)
                    if bytes_written != len(data):
                        raise IOError(f"Incomplete write to temporary file '{file_path}'")
                    os.fchmod(fd, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
                finally:
                    if fd >= 0:
                        os.close(fd)
                        fd = -1
            else:
                file_path = path
                try:
                    fd = os.open(file_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, stat.S_IRWXU)
                except OSError as e:
                    if e.errno == errno.EACCES:
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
                    os.fchmod(fd, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
                finally:
                    if fd >= 0:
                        os.close(fd)
                        fd = -1

            ro_fd = os.open(file_path, os.O_RDONLY | os.O_CLOEXEC)
            if ro_fd < 0:
                err = ctypes.get_errno()
                if os.path.exists(file_path):
                    if is_temp:
                        try:
                            os.unlink(file_path)
                        except OSError:
                            pass
                    else:
                        logging.error(f"[-] Warning: Executable written to '{file_path}' but failed to reopen read-only.")
                raise OSError(err, f"Failed to reopen '{file_path}' read-only: {os.strerror(err)}")

            return ExecutableFile(ro_fd, file_path, is_temp)

        except Exception as e:
            logging.error(f"[-] Error writing executable: {e}")
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if ro_fd >= 0:
                try:
                    os.close(ro_fd)
                except OSError:
                    pass
            if is_temp and file_path and os.path.exists(file_path):
                try:
                    os.unlink(file_path)
                except OSError:
                    pass
            return None

    @staticmethod
    def cleanup(exe_file_obj: ExecutableFile | None):
        if exe_file_obj is None:
            return
        exe_file_obj.close()
        temp_path = exe_file_obj.temp_path
        if temp_path:
            try:
                os.unlink(temp_path)
                logging.info(f"[+] Cleaned up temporary file: {temp_path}")
            except FileNotFoundError:
                pass
            except OSError as e:
                logging.warning(f"[-] Warning: Failed to clean up temporary file '{temp_path}': {e}")


