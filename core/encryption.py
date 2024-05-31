import string
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def vigenere_encrypt(plaintext, key):
    encrypted_message = ""
    key_index = 0

    for char in plaintext:
        if char in string.ascii_letters:
            shift = ord(key[key_index].upper()) - ord('A')
            encrypted_char = chr((ord(char.upper()) - ord('A') + shift) % 26 + ord('A'))
            encrypted_message += encrypted_char
            key_index = (key_index + 1) % len(key)
        else:
            encrypted_message += char

    return encrypted_message


def vigenere_decrypt(ciphertext, key):
    decrypted_message = ""
    key_index = 0

    for char in ciphertext:
        if char in string.ascii_letters:
            shift = ord(key[key_index].upper()) - ord('A')
            decrypted_char = chr((ord(char.upper()) - ord('A') - shift) % 26 + ord('A'))
            decrypted_message += decrypted_char
            key_index = (key_index + 1) % len(key)
        else:
            decrypted_message += char

    return decrypted_message


def encrypt_file_with_key_iv(input_filename, output_filename, key, iv):
    file_extension = os.path.splitext(input_filename)[1].encode()
    file_extension_len = len(file_extension).to_bytes(1, 'big')

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    with open(input_filename, 'rb') as f:
        plaintext = f.read()

    padded_data = padder.update(file_extension_len + file_extension + plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_filename, 'wb') as f:
        f.write(iv + ciphertext)


def decrypt_file_with_key_iv(input_filename, output_filename, key):
    with open(input_filename, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext_with_extension = unpadder.update(padded_plaintext) + unpadder.finalize()

    file_extension_len = plaintext_with_extension[0]
    file_extension = plaintext_with_extension[1:1 + file_extension_len].decode()
    plaintext = plaintext_with_extension[1 + file_extension_len:]

    output_filename_with_extension = os.path.splitext(output_filename)[0] + file_extension

    with open(output_filename_with_extension, 'wb') as f:
        f.write(plaintext)
