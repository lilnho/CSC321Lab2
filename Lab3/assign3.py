import Crypto
import random
import hashlib
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def diffie_ver1(p, g):
    # Alice
    if (isinstance(p, str)):
        p = int(p, 16)

    if (isinstance(g, str)):
        g = int(g, 16)

    a = random.randint(0, p)
    #A = (g^a)%p
    A = pow(g, a, p)
    # send A

    # Bob
    b = random.randint(0, p)
    #B = (g^b)%p
    B = pow(g, b, p)
    # send B

    # Alice
    #sA = (pow(B,a))%p
    sA = pow(B, a, p)
    k1 = SHA256.new()
    sA_BL = sA.to_bytes((sA.bit_length() + 7) // 8, byteorder='big')
    k1.update(sA_BL)
    # sA_bytes = str(sA).encode('utf-8')
    # k1 = hashlib.sha256(sA_bytes).hexdigest()[:16]
    m0 = "Hi Bob!"
    m0 = pad(m0)
    cipher = AES.new(k1.digest()[:16], AES.MODE_CBC)
    cA = cipher.encrypt(m0.encode('utf-8'))

    # send cA
    print(cA)
    print("key 1", k1.digest())
    # Bob
    #sB = pow(A, b)%p
    sB = pow(A, b, p)
    k2 = SHA256.new()
    sB_BL = sB.to_bytes((sB.bit_length() + 7) // 8, byteorder='big')
    k2.update(sB_BL)
    m1 = "Hi Alice"
    m1 = pad(m1)
    cipher2 = AES.new(k2.digest()[:16], AES.MODE_CBC)
    cB = cipher2.encrypt(m1.encode('utf-8'))

    # send cB
    print(cB)
    print("key 2", k2.digest())

# def diffie_ver2(p, q):


def main():
    p = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
    "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
    "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
    "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
    "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
    "DF1FB2BC2E4A4371"
    g = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
    "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
    "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
    "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
    "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
    "855E6EEB22B3B2E5"

    diffie_ver1(p, g)

if __name__ == "__main__":
    main()






