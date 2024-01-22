from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

BLOCKSIZE = 1024

def main(file_name):
    temp = 0
    aes_key = get_random_bytes(16)
    IV = get_random_bytes(16)
    
    #ECB
        file_name.read(BLOCKSIZE)

    try:
        file_size = os.path.getsize(file_name)
        overflow_size = file_size % BLOCKSIZE
    except FileNotFoundError:
        print(f"Error File '{filename}' not found.")

    # PKCS#7 Padding
    if overflow_size != 0:
        try:
            with open(file_name, 'rb') as fi

if __name__ == "__main__":
    main()