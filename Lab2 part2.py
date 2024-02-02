import Crypto
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

Crypto.Cipher.AES.MODE_ECB = 1
BLOCKSIZE = 16

def pkcs7(file_data):
    overflow_size = (len(file_data) % BLOCKSIZE)
    pad_size = 16 - overflow_size
    
    pad = bytes([pad_size] * pad_size)
    return file_data + pad
    
def ecb(file_data):
    aes_key = get_random_bytes(16)

    data = pkcs7(file_data)
    
    
    cipher = AES.new(aes_key,AES.MODE_ECB)
    ciphertext = cipher.encrypt(data)

    return ciphertext

def cbc(file_data, iv, cipher):
    data = pkcs7(file_data)
    numBlocks = len(file_data) // BLOCKSIZE

    encrypted = b''
    
    for block in range(numBlocks+1):
        block_data = data[block * 16: (block + 1) * 16]
        xor = bytes(x^y for x,y in zip(iv, block_data))
        ciphertext = cipher.encrypt(xor)
        iv = ciphertext
        encrypted += ciphertext
    
    return encrypted

def cbc_decrypt(ciphertext, iv, cipher):
    numBlocks = len(ciphertext) // BLOCKSIZE
    decrypted = b''

    for block in range(numBlocks+1):
        block_data = ciphertext[block * 16: (block + 1) * 16]
        decrypt_block = cipher.decrypt(block_data)
        xor = bytes(x^y for x,y in zip(iv, decrypt_block))
        decrypted += xor
        iv = block_data

    return decrypted

    # last_block = ciphertext[(numBlocks - 1) *16: numBlocks * 16]
    # last_key = last_block.decrypt(aes_key)
    # for block in range(numBlocks - 1,0,-1):
    #     iv = ciphertext[(block - 1) *16: block *16]
    #     xor = bytes(x^y for x,y in zip(iv,last_key))
    #     last_block = iv
    #     decrypted += xor
    #     last_key = last_block.decrypt(aes_key)

def submit(arb_string, iv, aes_key):
    new_string = "userid=456;userdata=" + arb_string + ";session-id=31337"
    new_string = new_string.replace(";", "%3B")
    new_string = new_string.replace("=", "%3D")
    new_string = bytes(new_string, 'utf-8')
    return cbc(new_string, iv, aes_key)
    

def verify(arb_string, iv, cipher):
    newstring = bytes(cbc_decrypt(arb_string, iv, cipher))
    print(newstring)
    deco = newstring.decode("iso-8859-1")
    print(deco)
    
    return ";admin=true;" in deco

def modify(ciphertext):
    blockone = ciphertext[0:16]
    xor =bytes(x^y for x,y in zip(blockone, blockone))
    #emp = bytes(x^y for x,y in zip(xor, bytes(';admin=true;','utf-8'))) 
    #res = ciphertext.replace(ciphertext[0:16], pkcs7(temp)) 
    return ciphertext 

def main():
    iv = get_random_bytes(16)
    aes_key = get_random_bytes(16)

    cipher = AES.new(aes_key,AES.MODE_ECB)

    msg = input("Enter your message: ")  
    encrypted = submit(msg ,iv,cipher)
    mod = modify(encrypted)
    decrypted = verify(mod,iv, cipher)
    
    print(decrypted)

    

if __name__ == "__main__":
    main()