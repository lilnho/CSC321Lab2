import Crypto
import random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

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
    sA = (B^a)%p
    k1 = SHA256.new()
    k1.update(str(sA))
    m0 = "Hi Bob!"
    cipher = AES.new(k1, AES.MODE_CBC)
    cA = cipher.encrypt(m0)

    # send cA
    print(cA)

    # Bob
    sB = (A^b)%p
    k2 = SHA256.new()
    k2.update(str(sB))
    m1 = "Hi Alice"
    cipher2 = AES.new(k2, AES.MODE_CBC)
    cB = cipher2.encrypt(m1)

    # send cB
    print(cB)

# def diffie_ver2(p, q):


def main():
    diffie_ver1(8, 10)

if __name__ == "__main__":
    main()






