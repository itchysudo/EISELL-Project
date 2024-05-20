def vigenere_encrypt(plaintext, key):
    encrypted_message = []
    key = key.upper()
    key_index = 0

    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index]) - ord('A')
            if char.isupper():
                encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            print(f"Encrypting {char} with shift {shift}: {encrypted_char}")  # Debug statement
            encrypted_message.append(encrypted_char)
            key_index = (key_index + 1) % len(key)
        else:
            encrypted_message.append(char)

    return ''.join(encrypted_message)

def vigenere_decrypt(ciphertext, key):
    decrypted_message = []
    key = key.upper()
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index]) - ord('A')
            if char.isupper():
                decrypted_char = chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
            else:
                decrypted_char = chr((ord(char) - ord('a') - shift + 26) % 26 + ord('a'))
            print(f"Decrypting {char} with shift {shift}: {decrypted_char}")  # Debug statement
            decrypted_message.append(decrypted_char)
            key_index = (key_index + 1) % len(key)
        else:
            decrypted_message.append(char)

    return ''.join(decrypted_message)
