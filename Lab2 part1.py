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
#   numBlocks = len(file_data) // BLOCKSIZE
    
    
    cipher = AES.new(aes_key,AES.MODE_ECB)
    ciphertext = cipher.encrypt(data)

    return ciphertext

def cbc(file_data):
    aes_key = get_random_bytes(16)
    iv = get_random_bytes(16)

    data = pkcs7(file_data)
    numBlocks = len(file_data) // BLOCKSIZE
    
    encrypted = b''
    cipher = AES.new(aes_key,AES.MODE_ECB)
    for block in range(numBlocks):
        block_data = data[block * 16: (block + 1) * 16]
        #xor = bitwise_xor_bytes(block_data, aes_key)
        #for x,y in zip(iv, block_data):
        xor = bytes(x^y for x,y in zip(iv, block_data))
        ciphertext = cipher.encrypt(xor)
        iv = ciphertext
        encrypted += ciphertext
    
    return encrypted

def main(file_name):
    IV = get_random_bytes(16)

    try:
        file_size = os.path.getsize(file_name)
        overflow_size = file_size % BLOCKSIZE
    except FileNotFoundError:
        print(f"Error File '{file_name}' not found.")

    # PKCS#7 Padding
    if overflow_size != 0:
        try:
            with open(file_name, 'rb') as file:
                #BMP header = 54 bytes
                bmp_hdr = file.read(54)
                file_data = file.read()
        except FileNotFoundError:
            print(f"Error File '{file_name}' not found.")
    
    
    encrypted = ecb(file_data)
    enc2 = cbc(file_data)
    
    #preserve and reappend BMP header as plaintext
    encrypted_bmp = bmp_hdr + encrypted
    enc_bmp = bmp_hdr + enc2
    
    with open("encrypted.bmp", 'wb') as ecb_file:
        ecb_file.write(encrypted_bmp)

    with open("enc2.bmp", 'wb') as ecb_file:
        ecb_file.write(enc_bmp)
    

if __name__ == "__main__":
    main("cp-logo.bmp")