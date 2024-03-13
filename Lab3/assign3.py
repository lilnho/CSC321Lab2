import Crypto
import random
import string
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
from Crypto.Util.number import getPrime
from Crypto.Util.number import bytes_to_long, long_to_bytes

#TASK I
def pad_me(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def diffie(p, g):
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
    m0 = pad_me(m0)
    cipher = AES.new(k1.digest()[:16], AES.MODE_CBC)
    cA = cipher.encrypt(m0.encode('utf-8'))

    # send cA

    # Bob
    #sB = pow(A, b)%p
    sB = pow(A, b, p)
    k2 = SHA256.new()
    sB_BL = sB.to_bytes((sB.bit_length() + 7) // 8, byteorder='big')
    k2.update(sB_BL)
    m1 = "Hi Alice"
    m1 = pad_me(m1)
    cipher2 = AES.new(k2.digest()[:16], AES.MODE_CBC)
    cB = cipher2.encrypt(m1.encode('utf-8'))

    # send cB

    return k1.digest, k2.digest()

#Task II: tampering with A and B
def diffie_attack1(p, g):
    iv = get_random_bytes(16)
    
    # Alice
    if (isinstance(p, str)):
        p = int(p, 16)

    if (isinstance(g, str)):
        g = int(g, 16)

    a = random.randint(0, p)
    A = pow(g, a, p)
    # send A
    
    # Mallory changes A -> p
    A = p

    # Bob
    b = random.randint(0, p)
    B = pow(g, b, p)
    # send B
    
    # Mallory changes B -> p
    B = p

    # Alice
    sA = pow(B, a, p)
    k1 = SHA256.new()
    sA_BL = sA.to_bytes((sA.bit_length() + 7) // 8, byteorder='big')
    k1.update(sA_BL)

    m0 = "Hi Bob!"
    m0 = pad_me(m0)
    cipher = AES.new(k1.digest()[:16], AES.MODE_CBC, iv)
    cA = cipher.encrypt(m0.encode('utf-8'))

    # send cA
    # Bob
    sB = pow(A, b, p)
    k2 = SHA256.new()
    sB_BL = sB.to_bytes((sB.bit_length() + 7) // 8, byteorder='big')
    k2.update(sB_BL)
    m1 = "Hi Alice"
    m1 = pad_me(m1)
    cipher2 = AES.new(k2.digest()[:16], AES.MODE_CBC, iv)
    cB = cipher2.encrypt(m1.encode('utf-8'))

    # send cB
    
    # Mallory decrypts message
    new_secret = 0 # p mod p = 0

    mallory_key = SHA256.new()
    msA_BL = new_secret.to_bytes((new_secret.bit_length() + 7) // 8, byteorder='big')
    mallory_key.update(msA_BL)
    
    cipherMA = AES.new(mallory_key.digest()[:16], AES.MODE_CBC, iv)
    cipherMB = AES.new(mallory_key.digest()[:16], AES.MODE_CBC, iv)

  
    alice_message = unpad(cipherMA.decrypt(cA), 16).decode('utf-8')
    
    bob_message = unpad(cipherMB.decrypt(cB), 16).decode('utf-8')
    
    print(alice_message)
    print(bob_message)
    
#Task II: Tampering with g
def diffie_attack2(p, g):
    iv = get_random_bytes(16)
    
    # Alice
    if (isinstance(p, str)):
        p = int(p, 16)

    if (isinstance(g, str)):
        g = int(g, 16)

    g = 1
    #g = p
    #g = p - 1

    a = random.randint(0, p)
    A = pow(g, a, p)
    # send A

    # Bob
    b = random.randint(0, p)
    B = pow(g, b, p)
    # send B

    # Alice
    sA = pow(B, a, p)
    k1 = SHA256.new()
    sA_BL = sA.to_bytes((sA.bit_length() + 7) // 8, byteorder='big')
    k1.update(sA_BL)
    m0 = "Hi Bob!"
    m0 = pad_me(m0)
    cipher = AES.new(k1.digest()[:16], AES.MODE_CBC, iv)
    cA = cipher.encrypt(m0.encode('utf-8'))

    # send cA
    # Bob
    sB = pow(A, b, p)
    k2 = SHA256.new()
    sB_BL = sB.to_bytes((sB.bit_length() + 7) // 8, byteorder='big')
    k2.update(sB_BL)
    m1 = "Hi Alice"
    m1 = pad_me(m1)
    cipher2 = AES.new(k2.digest()[:16], AES.MODE_CBC, iv)
    cB = cipher2.encrypt(m1.encode('utf-8'))

    # send cB
    
    # Mallory decrypts message
    # changing g to 1
    new_secret = 1 # 1 ^ anything mod [any positive int that isnt 1] = 1 
    # changing g to p
    #new_secret = 0 # p mod p = 0
    #changing g = p - 1
    #new_secret = 1 # if a/b is even, (p-1)^[even] mod p is 1
    #new_secret = p - 1 # if a/b is odd, (p-1)^[odd] mod p = p - 1
    

    mallory_key = SHA256.new()
    msA_BL = new_secret.to_bytes((new_secret.bit_length() + 7) // 8, byteorder='big')
    mallory_key.update(msA_BL)
    
    cipherMA = AES.new(mallory_key.digest()[:16], AES.MODE_CBC, iv)
    cipherMB = AES.new(mallory_key.digest()[:16], AES.MODE_CBC, iv)

    alice_message = unpad(cipherMA.decrypt(cA), 16).decode('utf-8')
    
    bob_message = unpad(cipherMB.decrypt(cB), 16).decode('utf-8')
    
    print(alice_message)
    print(bob_message)
    
#TASK III
def rsa_encrypt(message):
    m = int(message.encode('utf-8').hex(), 16)
    p = getPrime(2048)
    q = getPrime(2048)
    n = p*q
    phi = (p-1)*(q-1) # least common multiple of p-1 and q-1
    e = 65537
    c = pow(m, e, n)
    return c, n, phi


# Global Variables
x, y = 0, 1
 
def gcd_extended(a, b):
    global x, y

    if (a == 0):
        x = 0
        y = 1
        return b
 
    gcd = gcd_extended(b % a, a)
    x1 = x
    y1 = y
 
    x = y1 - (b // a) * x1
    y = x1
 
    return gcd
 
 
def mod_inverse(e, phi):
 
    g = gcd_extended(e, phi)
    if (g != 1):
        raise ValueError("DNE")
 
    else:
        res = (x % phi + phi) % phi
        return res


def rsa_decrypt(phi, c, n):
    e = 65537
    d = mod_inverse(e, phi)
    #d = pow(e, -1, phi)

    m = pow(int(c), int(d), int(n))
    hex_s = hex(m)[2:]
    message = bytes.fromhex(hex_s).decode('utf-8')
    return message

def rsa_attack(s, n, e, phi):
    # uses e, n from alice and s from bob
    c = pow(s, e, n)
    # mallory modifies c
    c_prime = n * c
    # alice decrypts the modified c
    d = mod_inverse(e, phi)
    s = pow(int(c_prime), int(d), int(n))

    # mallory encrypts her message with s
    key = SHA256.new(long_to_bytes(s)).digest()
    m = "Hi Bob!"
    cipher = AES.new(key, AES.MODE_CBC)
    padded_message = pad(m.encode('utf-8'), AES.block_size)
    c_zero = cipher.encrypt(padded_message)

    # mallory 
    s_mallory = 0
    key_mallory = SHA256.new(long_to_bytes(s_mallory)).digest()
    cipher_mallory = AES.new(key_mallory, AES.MODE_CBC, cipher.iv)
    attack_mallory = cipher_mallory.decrypt(c_zero)
    attack_mallory = unpad(attack_mallory, AES.block_size).decode('utf-8')
    return attack_mallory

#Task IV
def sha256_encrypt(message):
    m = message.encode('utf-8')
    k1 = SHA256.new()
    k1.update(m)
    result = k1.digest()
    return result.hex()

def sha256_collision(limit):
    test = ''.join(random.choices(string.ascii_letters, k=5))
    btest = bytearray(test, 'utf-8')
    bittest = btest[0:limit]
    outputs = {}
    count = 0
    loop = False
    while loop == False:
        output = sha256_encrypt(test)
        if bittest in outputs:
            loop = True
        else:
            outputs[count] = bittest
            count +=1
            test = ''.join(random.choices(string.ascii_letters, k=5))
    if loop == true:
        return count
    
        
            
    
    
    
    



def main():
    # p = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
    # "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
    # "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
    # "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
    # "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
    # "DF1FB2BC2E4A4371"
    # g = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
    # "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
    # "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
    # "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
    # "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
    # "855E6EEB22B3B2E5"

    # k1, k2 = diffie(p, g)
    # if k1 == k2:
    #     print("Diffie successful. Alice and Bobs' keys match.")

    # diffie_attack1(p, g)
    # diffie_attack2(p, g)
    # c, n, phi = rsa_encrypt("hello")
    # m = rsa_decrypt(phi, c, n)
    # if m == "hello":
    #     print("RSA encrypt and decrypt successful. Messages match.")

    # c, n, phi = rsa_encrypt("hi my name is keila")
    # m = rsa_decrypt(phi, c, n)
    # if m == "hi my name is keila":
    #     print("RSA encrypt and decrypt successful. Messages match.")


    # p = getPrime(2048)
    # q = getPrime(2048)
    # p = 5
    # q = 11
    # n = p*q
    # phi = (p-1)*(q-1)
    # c_zero = rsa_attack(7, n, 3, phi)
    # if c_zero == "Hi Bob!":
    #     print("RSA Attack successful. Mallory decrypted Alice's message.")

    t4 = sha256_encrypt("hello")
    print(t4)
    t5 = sha256_encrypt("jello")
    print(t5)

    sha256_collision(8)

if __name__ == "__main__":
    main()






