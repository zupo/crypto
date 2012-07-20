ct = "20814804c1767293b99f1d9cab3bc3e7ac1e37bfb15599e5f40eef805488281d".decode('hex')
iv = ct[:16]


def strxor(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])


def main():
    print 'cpyther text: %s' % ct
    print 'IV          : %s' % iv
    xored_part = strxor(strxor(iv[8], '1'), '5')
    new_iv = iv[:8] + xored_part + iv[9:]
    print 'new IV      : %s' % new_iv
    new_ct = new_iv + ct[16:]
    print 'new ct:     : %s' % new_ct.encode('hex')


if __name__ == '__main__':
    main()
