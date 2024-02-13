import Crypto
import random
import hashlib
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def diffie_ver1(p, g):
    # Alice
    a = random.randint(0, p)
    A = (g^a)%p
    # send A

    # Bob
    b = random.randint(0, p)
    B = (g^b)%p
    # send B

    # Alice
    sA = (pow(B,a))%p
    k1 = SHA256.new()
    sA_BL = sA.to_bytes(2, byteorder='big')
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
    sB = pow(A, b)%p
    k2 = SHA256.new()
    sB_BL = sB.to_bytes(2, byteorder='big')
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
    diffie_ver1(8, 10)

if __name__ == "__main__":
    main()






