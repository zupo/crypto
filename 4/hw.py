# dependencies:
# * requests

import requests
import string

TARGET = 'http://crypto-class.appspot.com/po?er='
CT = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'.decode('hex')

FAST_CHARLIST = ' etaonisrhldcupfmwybgvkqxjzETAONISRHLDCUPFMWYBGVKQXJZ,.!'
COMPLETE_CHARLIST = string.printable


def strxor(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])


def chunks(l, n):
    return [l[i:i + n] for i in range(0, len(l), n)]


def query(ct):
    r = requests.get(TARGET + ct.encode('hex'))
    # print "We got: %d" % r.status_code
    if r.status_code == 404:
        return True  # good padding
    return False  # bad padding


if __name__ == "__main__":

    print 'splitting CT into blocks ...'
    IV = CT[:16]
    blocks = []
    for i in range(16, len(CT), 16):
        blocks.append(CT[i:i + 16])

    print "CT     : %s" % CT.encode('hex')
    print "IV     : %s" % IV.encode('hex')
    for i, block in enumerate(blocks):
        print "M%i     : %s" % (i, block.encode('hex'))

    print 'start attack for block 0'
    pt0 = ['?' for i in range(16)]
    prev_block = IV
    block = blocks[0]

    for i in range(15, -1, -1):
        print 'guessing byte %i' % i
        pad_len = 16 - i  # padding length

        for guess in FAST_CHARLIST:

            xored_section = ''

            # xor with guess and pad length
            xored_section += strxor(strxor(prev_block[i], guess), chr(pad_len))

            # xor with known characters and pad length
            for j in range(i + 1, 16):
                xored_section += strxor(strxor(prev_block[j], pt0[j]), chr(pad_len))

            # create the new previous block
            new_prev_block = prev_block[:i] + xored_section
            assert len(new_prev_block) == 16

            new_ct = new_prev_block + block
            if query(new_ct):
                print 'found it: %s' % guess
                pt0[i] = guess
                break

    print 'start attack for block 1'
    pt1 = ['?' for i in range(16)]
    prev_block = blocks[0]
    block = blocks[1]

    for i in range(15, -1, -1):
        print 'guessing byte %i' % i
        pad_len = 16 - i  # padding length

        for guess in FAST_CHARLIST:

            xored_section = ''

            # xor with guess and pad length
            xored_section += strxor(strxor(prev_block[i], guess), chr(pad_len))

            # xor with known characters and pad length
            for j in range(i + 1, 16):
                xored_section += strxor(strxor(prev_block[j], pt1[j]), chr(pad_len))

            # create the new previous block
            new_prev_block = prev_block[:i] + xored_section
            assert len(new_prev_block) == 16

            new_ct = IV + new_prev_block + block
            if query(new_ct):
                print 'found it: %s' % guess
                pt1[i] = guess
                break

    print 'start attack for block 2'
    pt1 = ['?' for i in range(16)]
    prev_block = blocks[0]
    block = blocks[1]

    for i in range(15, -1, -1):
        print 'guessing byte %i' % i
        pad_len = 16 - i  # padding length

        for guess in FAST_CHARLIST:

            xored_section = ''

            # xor with guess and pad length
            xored_section += strxor(strxor(prev_block[i], guess), chr(pad_len))

            # xor with known characters and pad length
            for j in range(i + 1, 16):
                xored_section += strxor(strxor(prev_block[j], pt1[j]), chr(pad_len))

            # create the new previous block
            new_prev_block = prev_block[:i] + xored_section
            assert len(new_prev_block) == 16

            new_ct = IV + new_prev_block + block
            if query(new_ct):
                print 'found it: %s' % guess
                pt1[i] = guess
                break

    print ''.join(pt0 + pt1)
