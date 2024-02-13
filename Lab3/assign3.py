import Crypto
import random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

def diffie(p, g):

    # Alice
    a = random.randint(0, p)
    A = (g^a)%p


    b = random.randint(0, p)
    B = (g^b)%p

    sA = (B^a)%p
    k = SHA256.new()
    k.update(str(sA))
    m = "Hi Bob!"
    cA = 






