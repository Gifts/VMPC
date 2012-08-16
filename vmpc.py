#!/usr/bin/env python
#coding: utf8

import array
import itertools

class VMPC(object):
    def __init__(self, level=3):
        self._P = array.array('B', range(256))
        self._S = 0
        self._stream_generator = None

    def KSA(self, cipher_key, cipher_IV=None, KSA_version=1):
        assert(type(cipher_key) is str)
        assert(16 <= len(cipher_key) <= 64)

        if cipher_IV is not None:
            assert(type(cipher_IV) is str)
            assert(16 <= len(cipher_IV) <= 64)

        if KSA_version == 2:
            assert(type(cipher_IV) is str)

        self._S = 0
        self._P = array.array('B', range(256))

        self._KSA(cipher_key)
        if cipher_IV is not None:
            self._KSA(cipher_IV)
        if KSA_version == 2:
            self._KSA(cipher_key)

    def _KSA(self, cipher_key):
        tmp_key = array.array('B', cipher_key)
        tmp_length = len(tmp_key)
        tmp_S = self._S
        tmp_P = self._P

        for m in xrange(768):
            n = m & 255
            tmp_S = tmp_P[(tmp_S + tmp_P[n] + tmp_key[m % tmp_length]) & 255]
            tmp_P[tmp_S], tmp_P[n] = tmp_P[n], tmp_P[tmp_S]

        self._S = tmp_S
        self._P = tmp_P

    def crypt(self, data):
        assert(
            type(data) is str
            or type(data) is array.array
            )
        if self._stream_generator is None:
            #self._stream_generator = self._cipher_stream()
            self._stream_generator2 = self._cipher_stream_chunk()
            self._stream_generator2.send(None)
        tmp_data = array.array('B', data)
        tmp_crypt = self._stream_generator2.send(len(tmp_data))
        for pos, value in enumerate(tmp_data):
            tmp_data[pos] ^= tmp_crypt[pos]
        #tmp_result = array.array('B', itertools.imap(lambda x, y: x ^ y, tmp_data, ))
        return tmp_data.tostring()
    decrypt = crypt

    def _cipher_stream_chunk(self, chunk=1024):
        n = 0
        tmp_P = self._P
        chunk = yield 'OK'
        while 1:
            tmp_result = []#array.array('B')
            S = self._S
            for i in xrange(chunk):
                S = tmp_P[(S + tmp_P[n]) & 255]
                tmp_result.append(tmp_P[
                      (tmp_P[tmp_P[S]] + 1) & 255
                ])
                tmp_P[n], tmp_P[S] = tmp_P[S], tmp_P[n]
                n = (n + 1) & 255
            self._S = S
            chunk = yield array.array('B', tmp_result)

    def _cipher_stream(self):
        tmp_gen = self._cipher_stream_chunk()
        tmp_gen.next()
        while 1:
            for byte in tmp_gen.send(1024):
                yield byte

if __name__ == '__main__':
    test = VMPC()
    test.KSA('a' * 16)
    test.crypt('\0' * 1024 * 1024)