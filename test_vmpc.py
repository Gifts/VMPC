#coding: utf8
import array
import unittest
import vmpc
from binascii import unhexlify

try:
    xrange = xrange
except NameError:
    xrange = range

class TestStream(unittest.TestCase):
    def setUp(self):
        self.vmpc_object = vmpc.VMPC()

    def test_stream1(self):
        key = unhexlify('9661410AB797D8A9EB767C21172DF6C7')
        IV = unhexlify('4B5C2F003E67F39557A8D26F3DA2B155')
        self.vmpc_object.KSA(key, IV)

        result = array.array('B')
        stream = self.vmpc_object._cipher_stream()
        for i in xrange(102400):
            result.append(next(stream))
        result_string = result.tostring()

        self.assertEqual(
            result_string[0:4],
            unhexlify('a82479f5')
        )
        self.assertEqual(
            result_string[252:256],
            unhexlify('b8fc66a4')
        )
        self.assertEqual(
            result_string[1020:1024],
            unhexlify('e05640a5')
        )
        self.assertEqual(
            result_string[102396:102400],
            unhexlify('81ca499a')
        )

    def test_stream2(self):
        key = unhexlify('9661410AB797D8A9EB767C21172DF6C7')
        IV = unhexlify('4B5C2F003E67F39557A8D26F3DA2B155')
        self.vmpc_object.KSA(key, IV, 2)

        result = array.array('B')
        stream = self.vmpc_object._cipher_stream()
        for i in xrange(102400):
            result.append(next(stream))
        result_string = result.tostring()

        self.assertEqual(
            result_string[0:4],
            unhexlify('b6ebaefe')
        )
        self.assertEqual(
            result_string[252:256],
            unhexlify('48172473')
        )
        self.assertEqual(
            result_string[1020:1024],
            unhexlify('1daec35a')
        )
        self.assertEqual(
            result_string[102396:102400],
            unhexlify('1da7e1dc')
        )

    def test_crypt1(self):
        key = unhexlify('9661410AB797D8A9EB767C21172DF6C7')
        IV = unhexlify('4B5C2F003E67F39557A8D26F3DA2B155')
        self.vmpc_object.KSA(key, IV)

        result_string = self.vmpc_object.crypt(b'\0' * 102400)
        self.assertEqual(
            result_string[0:4],
            unhexlify('a82479f5')
        )
        self.assertEqual(
            result_string[252:256],
            unhexlify('b8fc66a4')
        )
        self.assertEqual(
            result_string[1020:1024],
            unhexlify('e05640a5')
        )
        self.assertEqual(
            result_string[102396:102400],
            unhexlify('81ca499a')
        )

    def test_crypt2(self):
        key = unhexlify('9661410AB797D8A9EB767C21172DF6C7')
        IV = unhexlify('4B5C2F003E67F39557A8D26F3DA2B155')
        self.vmpc_object.KSA(key, IV)

        result_string = self.vmpc_object.crypt(b'\0' * 51200)
        result_string += self.vmpc_object.crypt(b'\0' * 51200)

        self.assertEqual(
            result_string[0:4],
            unhexlify('a82479f5')
        )
        self.assertEqual(
            result_string[252:256],
            unhexlify('b8fc66a4')
        )
        self.assertEqual(
            result_string[1020:1024],
            unhexlify('e05640a5')
        )
        self.assertEqual(
            result_string[102396:102400],
            unhexlify('81ca499a')
        )


class TestAsserts(unittest.TestCase):
    def setUp(self):
        self.vmpc_object = vmpc.VMPC()

    def test_fail_KSA1(self):
        with self.assertRaises(AssertionError):
            self.vmpc_object.KSA(123456789)

    def test_fail_KSA2(self):
        with self.assertRaises(AssertionError):
            self.vmpc_object.KSA(b'123456')

    def test_fail_KSA3(self):
        with self.assertRaises(AssertionError):
            self.vmpc_object.KSA(b'a' * 150)

    def test_fail_KSA4(self):
        with self.assertRaises(AssertionError):
            self.vmpc_object.KSA(b'a' * 16, '1234')

    def test_fail_KSA5(self):
        with self.assertRaises(AssertionError):
            self.vmpc_object.KSA(b'a' * 16, b'a' * 150)

    def test_fail_KSA6(self):
        with self.assertRaises(AssertionError):
            self.vmpc_object.KSA(b'a' * 16, None, 2)

    def test_fail_KSA7(self):
        with self.assertRaises(AssertionError):
            self.vmpc_object.KSA(b'a' * 16, b'a' * 150)

    def test_fail_crypt1(self):
        self.vmpc_object.KSA(b'a' * 16, b'a' * 16)
        with self.assertRaises(AssertionError):
            self.vmpc_object.crypt(1)


class TestCrypt(unittest.TestCase):
    def setUp(self):
        self.vmpc_object_1 = vmpc.VMPC()
        self.vmpc_object_2 = vmpc.VMPC()

    def testEqualStreams1(self):
        key = b'a' * 16
        stream_length = 1024

        self.vmpc_object_1.KSA(key)
        self.vmpc_object_2.KSA(key)

        result1 = self.vmpc_object_1.crypt(b'\0' * stream_length)

        result2 = array.array('B')
        stream = self.vmpc_object_2._cipher_stream()

        for i in xrange(stream_length):
            result2.append(next(stream))
        result_string = result2.tostring()

        self.assertEqual(
            result1,
            result_string
        )


    def testEqualStreams2(self):
        key = b'a' * 16
        IV = b'b' * 16
        stream_length = 1024

        self.vmpc_object_1.KSA(key, IV)
        self.vmpc_object_2.KSA(key, IV)

        result1 = self.vmpc_object_1.crypt(b'\0' * stream_length)

        result2 = array.array('B')
        stream = self.vmpc_object_2._cipher_stream()

        for i in xrange(stream_length):
            result2.append(next(stream))
        result_string = result2.tostring()

        self.assertEqual(
            result1,
            result_string
        )

    def testEqualStreams3(self):
        key = b'a' * 16
        IV = b'b' * 16
        stream_length = 1024

        self.vmpc_object_1.KSA(key, IV, 2)
        self.vmpc_object_2.KSA(key, IV, 2)

        result1 = self.vmpc_object_1.crypt(b'\0' * stream_length)

        result2 = array.array('B')
        stream = self.vmpc_object_2._cipher_stream()

        for i in xrange(stream_length):
            result2.append(next(stream))
        result_string = result2.tostring()

        self.assertEqual(
            result1,
            result_string
        )

class TestCryptDecrypt(unittest.TestCase):
    def setUp(self):
        self.vmpc_object_1 = vmpc.VMPC()
        self.vmpc_object_2 = vmpc.VMPC()

    def test_crypt_decrypt1(self):
        key = b'a'*16
        text = b'0123456789' * 100

        self.vmpc_object_1.KSA(key)
        self.vmpc_object_2.KSA(key)

        crypt = self.vmpc_object_1.crypt(text)
        decrypt = self.vmpc_object_2.decrypt(crypt)

        self.assertEqual(
            text
            , decrypt
        )

    def test_crypt_decrypt2(self):
        key = b'a'*16
        IV = b'b' * 16
        text = b'0123456789' * 100

        self.vmpc_object_1.KSA(key, IV)
        self.vmpc_object_2.KSA(key, IV)

        crypt = self.vmpc_object_1.crypt(text)
        decrypt = self.vmpc_object_2.decrypt(crypt)

        self.assertEqual(
            text
            , decrypt
        )

    def test_crypt_decrypt3(self):
        key = b'a'*16
        IV = b'b' * 16
        text = b'0123456789' * 100

        self.vmpc_object_1.KSA(key, IV, 2)
        self.vmpc_object_2.KSA(key, IV, 2)

        crypt = self.vmpc_object_1.crypt(text)
        decrypt = self.vmpc_object_2.decrypt(crypt)

        self.assertEqual(
            text
            , decrypt
        )

