# deps: openssl, swig, M2Crypto, pycrypto

ENC = 1
DEC = 0

cbc_key1 = "140b41b22a29beb4061bda66b6747e14"
cbc_cyphertext1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"

cbc_key2 = "140b41b22a29beb4061bda66b6747e14"
cbc_cyphertext2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"

ctr_key1 = "36f18357be4dbd77f050515c73fcf9f2"
ctr_cyphertext1 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"

ctr_key2 = "36f18357be4dbd77f050515c73fcf9f2"
ctr_cyphertext2 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"


from M2Crypto.EVP import Cipher


def m2crypto_decrypt(key, iv, data):
    cipher = Cipher(alg='aes_128_cbc', key=key, iv=iv, op=DEC)
    v = cipher.update(data)
    v = v + cipher.final()
    return v


from Crypto.Cipher import AES


def pycrypto_decrypt(key, iv, data):
    crypt = AES.new(key, AES.MODE_CTR, counter=lambda: iv)
    return crypt.decrypt(data)


def main():

    # Question 1
    key = cbc_key1.decode('hex')
    iv = cbc_cyphertext1[:32].decode('hex')
    ct = cbc_cyphertext1[32:].decode('hex')
    print "pt1: '" + m2crypto_decrypt(key, iv, ct) + "'"

    # Question 2
    key = cbc_key2.decode('hex')
    iv = cbc_cyphertext2[:32].decode('hex')
    ct = cbc_cyphertext2[32:].decode('hex')
    print "pt2: '" + m2crypto_decrypt(key, iv, ct) + "'"

    # Question 3
    key = ctr_key1.decode('hex')
    iv1 = ctr_cyphertext1[:32].decode('hex')
    iv2 = hex(int(ctr_cyphertext1[:32], 16) + 1)[2:][:-1].decode('hex')  # iv+1
    iv3 = hex(int(ctr_cyphertext1[:32], 16) + 2)[2:][:-1].decode('hex')  # iv+2
    iv4 = hex(int(ctr_cyphertext1[:32], 16) + 3)[2:][:-1].decode('hex')  # iv+3
    ct1 = ctr_cyphertext1[32:64].decode('hex')
    ct2 = ctr_cyphertext1[64:96].decode('hex')
    ct3 = ctr_cyphertext1[96:128].decode('hex')
    ct4 = ctr_cyphertext1[128:].decode('hex')
    print "pt3: '" + pycrypto_decrypt(key, iv1, ct1) + pycrypto_decrypt(key, iv2, ct2) + pycrypto_decrypt(key, iv3, ct3) + pycrypto_decrypt(key, iv4, ct4) + "'"

    # Question 4
    key = ctr_key2.decode('hex')
    iv1 = ctr_cyphertext2[:32].decode('hex')
    iv2 = hex(int(ctr_cyphertext2[:32], 16) + 1)[2:][:-1].decode('hex')  # iv+1
    iv3 = hex(int(ctr_cyphertext2[:32], 16) + 2)[2:][:-1].decode('hex')  # iv+2
    iv4 = hex(int(ctr_cyphertext2[:32], 16) + 3)[2:][:-1].decode('hex')  # iv+3
    ct1 = ctr_cyphertext2[32:64].decode('hex')
    ct2 = ctr_cyphertext2[64:96].decode('hex')
    ct3 = ctr_cyphertext2[96:128].decode('hex')
    ct4 = ctr_cyphertext2[128:].decode('hex')
    print "pt4: '" + pycrypto_decrypt(key, iv1, ct1) + pycrypto_decrypt(key, iv2, ct2) + pycrypto_decrypt(key, iv3, ct3) + pycrypto_decrypt(key, iv4, ct4) + "'"


if __name__ == '__main__':
    main()
