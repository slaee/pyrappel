# Compile wrapper library with different architectures
```bash
$ gcc -shared -fPIC -o clib_wrapper_32.so clib_wrapper.c -m32
```

```bash
$ gcc -shared -fPIC -o clib_wrapper_64.so clib_wrapper.c
```