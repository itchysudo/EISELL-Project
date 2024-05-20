import string
# test message
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
