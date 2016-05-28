import sys
import random
import string
import time
import itertools
import operator
import base64

from Crypto.Cipher import AES
from Crypto.Hash import SHA256


def slow_foo():
    p = 181
    k = 2
    while k < p:
        if p % k == 0:
            return
        k += 1


def aes_enc(k, m):
    """
    Encrypt a message m with a key k in ECB mode using AES as follows:
    c = AES(k, m)

    Args:
      m should be a bytestring multiple of 16 bytes (i.e. a sequence of characters such as 'Hello...' or '\x02\x04...')
      k should be a bytestring of length exactly 16 bytes.

    Return:
      The bytestring ciphertext c
    """
    aes = AES.new(k)
    c = aes.encrypt(m)

    return c


def aes_dec(k, c):
    """
    Decrypt a ciphertext c with a key k in ECB mode using AES as follows:
    m = AES(k, c)

    Args:
      c should be a bytestring multiple of 16 bytes (i.e. a sequence of characters such as 'Hello...' or '\x02\x04...')
      k should be a bytestring of length exactly 16 bytes.

    Return:
      The bytestring message m
    """
    aes = AES.new(k)
    m = aes.decrypt(c)

    return m


def aes_enc_cbc(k, m, iv):
    """
    Encrypt a message m with a key k in CBC mode using AES as follows:
    c = AES(k, m)

    Args:
      m should be a bytestring multiple of 16 bytes (i.e. a sequence of characters such as 'Hello...' or '\x02\x04...')
      k should be a bytestring of length exactly 16 bytes.
      iv should be a bytestring of length exactly 16 bytes.

    Return:
      The bytestring ciphertext c
    """
    aes = AES.new(k, AES.MODE_CBC, iv)
    c = aes.encrypt(m)

    return c


def aes_dec_cbc(k, c, iv):
    """
    Decrypt a ciphertext c with a key k in CBC mode using AES as follows:
    m = AES(k, c)

    Args:
      c should be a bytestring multiple of 16 bytes (i.e. a sequence of characters such as 'Hello...' or '\x02\x04...')
      k should be a bytestring of length exactly 16 bytes.
      iv should be a bytestring of length exactly 16 bytes.

    Return:
      The bytestring message m
    """
    aes = AES.new(k, AES.MODE_CBC, iv)
    m = aes.decrypt(c)

    return m


def aes_cbc_mac(k, m):
    """
    Compute a CBC-MAC of message m with a key k using AES as follows:
    t = AES-CBC-MAC(k=(k1,k2), m),
    where k1 is used for the raw-CBC operation and k2 is used for the final
    encryption.

    k1 and k2 are derived from k as follows:
    [k1|k2] = SHA256(k | "CBC MAC keys")

    Note: the IV for CBC in this case will be 0.

    Args:
      m should be a bytestring multiple of 16 bytes (i.e. a sequence of characters such as 'Hello...' or '\x02\x04...')
      k should be a bytestring of length exactly 16 bytes.

    Return:
      The bytestring MAC t, of 16 bytes.
    """

    # Require good size
    m = m.ljust(16)
    k = k.ljust(16)

    # Derive the keys for raw-CBC and for the final tag
    res = SHA256.new(k + "CBC MAC keys").digest()
    k1 = res[0:16]
    k2 = res[16:32]

    # Get the MAC:
    # 1 - Do aes-CBC with k1 and iv=0, then keep only last block (last 16 bytes) of encryption
    res_1 = aes_enc_cbc(k1, m, 16 * '\x00')

    # 2 - Perform another AES encryption (simple, without CBC) on the last block from #1 using k2
    res_2 = aes_enc(k2, res_1[-16:])
    t = res_2
    # t = 16*'\x00'

    return t


def show_goodtag(message):
    key = "Cozonace si oua "

    # Get correct tag
    goodtag = aes_cbc_mac(key, message)
    # print "goodtag is:", goodtag.encode('hex')
    for i in goodtag:
        print i.encode('hex'),
    print ""

# Sa fie pe server
def verify(message, tag):
    key = 'Cozonace si oua '

    # Get correct tag
    goodtag = aes_cbc_mac(key, message)
    j = 0
    # Compare tags
    for i in range(16):
        # Artificially extend byte comparison duration
        # slow_foo()
        # if tag[i] != goodtag[i]:
        #     return False
        if tag[i] == goodtag[i]:
            # time.sleep(1 / 100000.0)
            j = j + 1

    time.sleep((1 * j) / 10000.0)
    # if (j > 0):
    #     print j
    if j == 16:
        return True
    else:
        return False


def hex_print(data):
    for k in data:
        print k.encode('hex'),
    print ""


def main():
    message = 'Hristos a inviat'

    show_goodtag(message)
    # Step 1. Iterate through all possible first byte values, and call the
    # Verify oracle for each of them
    # tag = 16*'\x00'
    # verify(message, tag)

    max_delta_chr = []
    for i in range(16):
        max_delta_chr.append('\x00')

    tag = 16 * '\x00'
    for j in range(15):
        max_delta = 0
        byte_no = -1
        for i in range(256):
            max_delta_chr[j] = chr(i)
            #tag = "".join(x for x in max_delta_chr)

            tag = tag[:j] + chr(i) + tag[j+1:]
            # print tag.encode('hex')

            t0 = time.time()
            #for z in range(100):
            verify(message, tag)
            t1 = time.time()

            delta = t1 - t0
            # if j == 14:
            #     print delta
            if delta > max_delta:
                max_delta = delta
                byte_no = i
        # print "max: ", byte_no
        max_delta_chr[j] = chr(byte_no)
        tag = tag[:j] + chr(byte_no) + tag[j+1:]
        hex_print(max_delta_chr)
        # print "byte ", j, " is ", max_delta_chr[j].encode('hex')
        # print max_delta_chr
        # break

    print "good:"
    show_goodtag(message)
    print "found:"
    hex_print(max_delta_chr)

    # j = j + 1
    #
    # # Step 2. Store the byte that caused the longest computation time
    #
    # # Step 3. Continue the operation for each byte (except the last)
    #
    # # Step 4. Guess the last byte, and query the oracle with the complete tag
    #
    # for i in range(256):
    #     max_delta_chr[j] = chr(i)
    #     mytag = "".join(x for x in max_delta_chr)
    #     result = verify(message, mytag)
    #     print result
    #     # print max_delta_chr
    #     if result == True:
    #         # print max_delta_chr
    #         print "Found tag: " + mytag
    #
    #         # print 'TAG: ' + tag
    #         # print 'MYTAG: ' + mytag


if __name__ == "__main__":
    main()
