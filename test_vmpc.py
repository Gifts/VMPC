#coding: utf8
import array
import unittest
import vmpc

class TestStream(unittest.TestCase):
    def setUp(self):
        self.vmpc_object = vmpc.VMPC()

    def test_stream1(self):
        key = '9661410AB797D8A9EB767C21172DF6C7'.decode('hex')
        IV = '4B5C2F003E67F39557A8D26F3DA2B155'.decode('hex')
        self.vmpc_object.KSA(key, IV)

        result = array.array('B')
        stream = self.vmpc_object._cipher_stream()
        for i in xrange(102400):
            result.append(stream.next())
        result_string = result.tostring()

        self.assertEqual(
            result_string[0:4],
            'a82479f5'.decode('hex')
        )
        self.assertEqual(
            result_string[252:256],
            'b8fc66a4'.decode('hex')
        )
        self.assertEqual(
            result_string[1020:1024],
            'e05640a5'.decode('hex')
        )
        self.assertEqual(
            result_string[102396:102400],
            '81ca499a'.decode('hex')
        )

    def test_crypt1(self):
        key = '9661410AB797D8A9EB767C21172DF6C7'.decode('hex')
        IV = '4B5C2F003E67F39557A8D26F3DA2B155'.decode('hex')
        self.vmpc_object.KSA(key, IV)

        result_string = self.vmpc_object.crypt('\0' * 102400)
        self.assertEqual(
            result_string[0:4],
            'a82479f5'.decode('hex')
        )
        self.assertEqual(
            result_string[252:256],
            'b8fc66a4'.decode('hex')
        )
        self.assertEqual(
            result_string[1020:1024],
            'e05640a5'.decode('hex')
        )
        self.assertEqual(
            result_string[102396:102400],
            '81ca499a'.decode('hex')
        )

    def test_crypt2(self):
        key = '9661410AB797D8A9EB767C21172DF6C7'.decode('hex')
        IV = '4B5C2F003E67F39557A8D26F3DA2B155'.decode('hex')
        self.vmpc_object.KSA(key, IV)

        result_string = self.vmpc_object.crypt('\0' * 51200)
        result_string += self.vmpc_object.crypt('\0' * 51200)

        self.assertEqual(
            result_string[0:4],
            'a82479f5'.decode('hex')
        )
        self.assertEqual(
            result_string[252:256],
            'b8fc66a4'.decode('hex')
        )
        self.assertEqual(
            result_string[1020:1024],
            'e05640a5'.decode('hex')
        )
        self.assertEqual(
            result_string[102396:102400],
            '81ca499a'.decode('hex')
        )


class TestAsserts(unittest.TestCase):
    def setUp(self):
        self.vmpc_object = vmpc.VMPC()

    def fail_KSA1(self):
        with self.assertRaises(AssertionError):
            self.vmpc_object.KSA(123456789)

    def fail_KSA2(self):
        with self.assertRaises(AssertionError):
            self.vmpc_object.KSA('123456')

    def fail_KSA3(self):
        with self.assertRaises(AssertionError):
            self.vmpc_object.KSA('a' * 150)

    def fail_KSA4(self):
        with self.assertRaises(AssertionError):
            self.vmpc_object.KSA('a' * 16, '1234')

    def fail_KSA5(self):
        with self.assertRaises(AssertionError):
            self.vmpc_object.KSA('a' * 16, 'a' * 150)

    def fail_KSA6(self):
        with self.assertRaises(AssertionError):
            self.vmpc_object.KSA('a' * 16, None, 2)

    def fail_KSA7(self):
        with self.assertRaises(AssertionError):
            self.vmpc_object.KSA('a' * 16, 'a' * 150)

    def fail_crypt1(self):
        self.vmpc_object.KSA('a' * 16, 'a' * 16)
        with self.assertRaises(AssertionError):
            self.vmpc_object.crypt(1)


class TestCrypt(unittest.TestCase):
    def setUp(self):
        self.vmpc_object_1 = vmpc.VMPC()
        self.vmpc_object_2 = vmpc.VMPC()

    def testEqualStreams1(self):
        key = 'a' * 16
        stream_length = 1024

        self.vmpc_object_1.KSA(key)
        self.vmpc_object_2.KSA(key)

        result1 = self.vmpc_object_1.crypt('\0' * stream_length)

        result2 = array.array('B')
        stream = self.vmpc_object_2._cipher_stream()

        for i in xrange(stream_length):
            result2.append(stream.next())
        result_string = result2.tostring()

        self.assertEqual(
            result1,
            result_string
        )


    def testEqualStreams2(self):
        key = 'a' * 16
        IV = 'b' * 16
        stream_length = 1024

        self.vmpc_object_1.KSA(key, IV)
        self.vmpc_object_2.KSA(key, IV)

        result1 = self.vmpc_object_1.crypt('\0' * stream_length)

        result2 = array.array('B')
        stream = self.vmpc_object_2._cipher_stream()

        for i in xrange(stream_length):
            result2.append(stream.next())
        result_string = result2.tostring()

        self.assertEqual(
            result1,
            result_string
        )

    def testEqualStreams3(self):
        key = 'a' * 16
        IV = 'b' * 16
        stream_length = 1024

        self.vmpc_object_1.KSA(key, IV, 2)
        self.vmpc_object_2.KSA(key, IV, 2)

        result1 = self.vmpc_object_1.crypt('\0' * stream_length)

        result2 = array.array('B')
        stream = self.vmpc_object_2._cipher_stream()

        for i in xrange(stream_length):
            result2.append(stream.next())
        result_string = result2.tostring()

        self.assertEqual(
            result1,
            result_string
        )