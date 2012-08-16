Unofficial implementation of VMPC (Variably Modified Permutation Composition) stream cipher.

Usage:
=======================

<code>
\>\>\> cipher = VMPC()
\>\>\> cipher.KSA('0123456789abcdef')
\>\>\> result = cipher.crypt('\0'*1024)
</code>

Caution:
=======================

There would be possible change in class interface to conform with other crypt libraries like PyCrypto