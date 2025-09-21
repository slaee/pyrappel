from ctypes import *

class IOVec(Structure):
    _fields_ = [
        ("iov_base", c_void_p),
        ("iov_len", c_size_t),
    ]


