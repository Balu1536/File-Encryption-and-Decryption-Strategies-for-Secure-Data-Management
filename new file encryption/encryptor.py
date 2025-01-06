import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class FileEncryptor:
    @staticmethod
    def encrypt_file(file_name, key):
        cipher = AES.new(key, AES.MODE_CBC)
        with open(file_name, 'rb') as file:
            plaintext = file.read()

        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        with open(file_name + '.enc', 'wb') as file:
            file.write(cipher.iv)  # Write the IV to the beginning of the file
            file.write(ciphertext)

    @staticmethod
    def decrypt_file(file_name, key):
        with open(file_name, 'rb') as file:
            iv = file.read(16)  # Read the IV
            ciphertext = file.read()

        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        with open(file_name[:-4], 'wb') as file:  # Remove .enc extension
            file.write(plaintext)