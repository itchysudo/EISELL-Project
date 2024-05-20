import unittest
from core.encryption import vigenere_encrypt, vigenere_decrypt

class TestEncryption(unittest.TestCase):

    def test_vigenere_encrypt(self):
        encrypted = vigenere_encrypt("HELLO", "KEY")
        print(f"Encrypting 'HELLO' with 'KEY': {encrypted}")
        self.assertEqual(encrypted, "RIJVS", f"Expected 'RIJVS' but got '{encrypted}'")

        encrypted = vigenere_encrypt("WORLD", "KEY")
        print(f"Encrypting 'WORLD' with 'KEY': {encrypted}")
        self.assertEqual(encrypted, "YQVNL", f"Expected 'YQVNL' but got '{encrypted}'")

    def test_vigenere_decrypt(self):
        decrypted = vigenere_decrypt("RIJVS", "KEY")
        print(f"Decrypting 'RIJVS' with 'KEY': {decrypted}")
        self.assertEqual(decrypted, "HELLO", f"Expected 'HELLO' but got '{decrypted}'")

        decrypted = vigenere_decrypt("YQVNL", "KEY")
        print(f"Decrypting 'YQVNL' with 'KEY': {decrypted}")
        self.assertEqual(decrypted, "WORLD", f"Expected 'WORLD' but got '{decrypted}'")

if __name__ == "__main__":
    unittest.main()
