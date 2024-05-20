import tkinter as tk
from tkinter import font, ttk, messagebox
from core.encryption import vigenere_encrypt, vigenere_decrypt

class EncryptionGUI:
    def __init__(self, master):
        self.master = master
        master.title("EISELL - Encrypted Integrity Stealthily Entropic Lattice")

        # Adjust font sizes for better visibility on macOS
        self.custom_font = font.Font(family="Consolas", size=12)
        self.title_font = font.Font(family="Consolas", size=14, weight="bold")
        self.footer_font = font.Font(family="Consolas", size=8)

        # Define light and dark color schemes
        self.colors = {
            "light": {"bg": "white", "fg": "black", "button_bg": "#eeeeee", "button_fg": "black"},
            "dark": {"bg": "#333333", "fg": "white", "button_bg": "#555555", "button_fg": "white"}
        }

        master.config(bg=self.colors["dark"]["bg"])  # Set background color for the main window

        self.label = tk.Label(master, text="Welcome to EISELL.", font=self.title_font, bg=self.colors["dark"]["bg"], fg=self.colors["dark"]["fg"])
        self.label.pack()

        # Create a frame to contain the buttons
        button_frame = tk.Frame(master, bg=self.colors["dark"]["bg"])
        button_frame.pack()

        # Configure the style for buttons
        self.style = ttk.Style()
        self.style.theme_use('default')
        self.style.configure('Dark.TButton', font=('Consolas', 10), background=self.colors["dark"]["button_bg"], foreground=self.colors["dark"]["button_fg"])
        self.style.map('Dark.TButton',
                       foreground=[('pressed', 'black'), ('active', 'black')],
                       background=[('pressed', '!disabled', self.colors["dark"]["button_bg"]), ('active', self.colors["dark"]["button_bg"])])

        # Adjust button width for better usability on macOS
        button_width = 20

        # Create buttons for encrypt, decrypt, and quit
        self.encrypt_button = ttk.Button(button_frame, text="Encrypt", command=self.open_encrypt_window, width=button_width, style='Dark.TButton')
        self.encrypt_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.decrypt_button = ttk.Button(button_frame, text="Decrypt", command=self.open_decrypt_window, width=button_width, style='Dark.TButton')
        self.decrypt_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.quit_button = ttk.Button(button_frame, text="Quit", command=master.quit, width=button_width, style='Dark.TButton')
        self.quit_button.pack(side=tk.LEFT, padx=5, pady=5)

        # Footer Label
        self.footer_label = tk.Label(master, text="Created by ItchySudo. Windows v1.2", font=self.footer_font, bg=self.colors["dark"]["bg"], fg=self.colors["dark"]["fg"])
        self.footer_label.pack(side=tk.BOTTOM)

    def open_encrypt_window(self):
        encrypt_window = tk.Toplevel(self.master)
        encrypt_window.title("Encrypt Message")
        encrypt_window.config(bg=self.colors["dark"]["bg"])  # Set background color

        self.plaintext_label = tk.Label(encrypt_window, text="Enter the message to encrypt:", font=self.custom_font, bg=self.colors["dark"]["bg"], fg=self.colors["dark"]["fg"])
        self.plaintext_label.pack()

        self.plaintext_entry = tk.Text(encrypt_window, width=50, height=5, font=self.custom_font, bg="black", fg="white")
        self.plaintext_entry.pack()

        self.key_label = tk.Label(encrypt_window, text="Enter the encryption key:", font=self.custom_font, bg=self.colors["dark"]["bg"], fg=self.colors["dark"]["fg"])
        self.key_label.pack()

        self.key_entry = tk.Entry(encrypt_window, font=self.custom_font, bg="black", fg="white")
        self.key_entry.pack()

        self.encrypt_button = ttk.Button(encrypt_window, text="Encrypt", command=lambda: self.encrypt_message(encrypt_window), style='Dark.TButton')
        self.encrypt_button.pack()

    def encrypt_message(self, encrypt_window):
        plaintext = self.plaintext_entry.get("1.0", tk.END).strip()
        key = self.key_entry.get().upper()

        encrypted_message = vigenere_encrypt(plaintext, key)

        result_label = tk.Label(encrypt_window, text=f"Encrypted message: {encrypted_message}", font=self.custom_font, bg=self.colors["dark"]["bg"], fg=self.colors["dark"]["fg"])
        result_label.pack()

        copy_button = ttk.Button(encrypt_window, text="Copy", command=lambda: self.copy_to_clipboard(encrypted_message), style='Dark.TButton')
        copy_button.pack()

        # Adjust window size to fit content
        encrypt_window.update_idletasks()
        encrypt_window.geometry(f"{encrypt_window.winfo_reqwidth()}x{encrypt_window.winfo_reqheight()}")

    def open_decrypt_window(self):
        decrypt_window = tk.Toplevel(self.master)
        decrypt_window.title("Decrypt Message")
        decrypt_window.config(bg=self.colors["dark"]["bg"])  # Set background color

        self.ciphertext_label = tk.Label(decrypt_window, text="Enter the message to decrypt:", font=self.custom_font, bg=self.colors["dark"]["bg"], fg=self.colors["dark"]["fg"])
        self.ciphertext_label.pack()

        self.ciphertext_entry = tk.Text(decrypt_window, width=50, height=5, font=self.custom_font, bg="black", fg="white")
        self.ciphertext_entry.pack()

        self.key_label = tk.Label(decrypt_window, text="Enter the decryption key:", font=self.custom_font, bg=self.colors["dark"]["bg"], fg=self.colors["dark"]["fg"])
        self.key_label.pack()

        self.key_entry = tk.Entry(decrypt_window, font=self.custom_font, bg="black", fg="white")
        self.key_entry.pack()

        self.decrypt_button = ttk.Button(decrypt_window, text="Decrypt", command=lambda: self.decrypt_message(decrypt_window), style='Dark.TButton')
        self.decrypt_button.pack()

    def decrypt_message(self, decrypt_window):
        ciphertext = self.ciphertext_entry.get("1.0", tk.END).strip()
        key = self.key_entry.get().upper()

        decrypted_message = vigenere_decrypt(ciphertext, key)

        result_label = tk.Label(decrypt_window, text=f"Decrypted message: {decrypted_message}", font=self.custom_font, bg=self.colors["dark"]["bg"], fg=self.colors["dark"]["fg"])
        result_label.pack()

        copy_button = ttk.Button(decrypt_window, text="Copy", command=lambda: self.copy_to_clipboard(decrypted_message), style='Dark.TButton')
        copy_button.pack()

        # Adjust window size to fit content
        decrypt_window.update_idletasks()
        decrypt_window.geometry(f"{decrypt_window.winfo_reqwidth()}x{decrypt_window.winfo_reqheight()}")

    def copy_to_clipboard(self, text):
        self.master.clipboard_clear()
        self.master.clipboard_append(text)

def main():
    root = tk.Tk()
    root.geometry("500x150")
    app = EncryptionGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
