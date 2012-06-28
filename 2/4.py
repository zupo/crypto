def strxor(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

print strxor('7b50baab07640c3d'.decode('hex'), 'ac343a22cea46d60'.decode('hex')).encode('hex')
print strxor('9f970f4e932330e4'.decode('hex'), '6068f0b1b645c008'.decode('hex')).encode('hex')
print strxor('2d1cfa42c0b1d266'.decode('hex'), 'eea6e3ddb2146dd0'.decode('hex')).encode('hex')
print strxor('9d1a4f78cb28d863'.decode('hex'), '75e5e3ea773ec3e6'.decode('hex')).encode('hex')
