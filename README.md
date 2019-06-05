Unofficial implementation of VMPC (Variably Modified Permutation Composition) stream cipher.

Usage:
=======================

```
>>> cipher = VMPC()<br>
>>> cipher.KSA(b'0123456789abcdef')
>>> result = cipher.crypt(b'\0'*1024)
```

Caution:
=======================

There would be possible change in class interface to conform with other crypt libraries like PyCrypto