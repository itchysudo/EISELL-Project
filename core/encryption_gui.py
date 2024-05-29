import tkinter as tk
from tkinter import font, ttk, messagebox, filedialog
from PIL import Image, ImageTk  # Import Pillow modules
from core.encryption import vigenere_encrypt, vigenere_decrypt
from core.snake_game import start_snake_game  # Import the start_snake_game function
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import secrets

class PythiaGUI:
    def __init__(self, master, footer_text):
        try:
            self.master = master
            self.footer_text = footer_text  # Store footer_text as an instance variable
            master.title("PYTHIA - Python Encryption Application")
            master.geometry("600x400")  # Increase default size

            # Initialize mode
            self.mode = "dark"

            # Adjust font sizes for better visibility
            self.custom_font = font.Font(family="Consolas", size=12)
            self.title_font = font.Font(family="Consolas", size=14, weight="bold")
            self.footer_font = font.Font(family="Consolas", size=8)

            # Define light and dark color schemes
            self.colors = {
                "light": {"bg": "white", "fg": "black", "button_bg": "#eeeeee", "button_fg": "black", "entry_bg": "white", "entry_fg": "black", "border_color": "#cccccc"},
                "dark": {"bg": "#333333", "fg": "white", "button_bg": "#555555", "button_fg": "white", "entry_bg": "black", "entry_fg": "white", "border_color": "#333333"}
            }

            # Configure the style for buttons
            self.style = ttk.Style()
            self.style.theme_use('default')

            # Create the layout
            self.create_layout()

            # Apply the initial color scheme
            self.apply_color_scheme()
            print("PythiaGUI initialized successfully.")
        except Exception as e:
            print(f"An error occurred in PythiaGUI initialization: {e}")

    def create_layout(self):
        try:
            # Clear window
            for widget in self.master.winfo_children():
                widget.destroy()

            # Create a menu bar
            menubar = tk.Menu(self.master)
            self.master.config(menu=menubar)

            # Add Help menu
            help_menu = tk.Menu(menubar, tearoff=0)
            menubar.add_cascade(label="Help", menu=help_menu)
            help_menu.add_command(label="Help", command=self.show_help)

            # Add Toggle mode menu
            menubar.add_command(label="Toggle Mode", command=self.toggle_mode)

            # Display the title text
            self.label = tk.Label(self.master, text="Welcome to PYTHIA.", font=self.title_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"])
            self.label.grid(row=0, column=0, columnspan=3, pady=10)

            # Create a frame to contain the main buttons
            self.button_frame = tk.Frame(self.master, bg=self.colors[self.mode]["bg"])
            self.button_frame.grid(row=1, column=0, padx=10, pady=10, sticky='n')

            # Create main buttons for text encrypt, file encrypt, key generator, snake game, and quit
            self.text_encrypt_button = ttk.Button(self.button_frame, text="Text Encryption", command=self.open_text_encryption_window)
            self.text_encrypt_button.pack(fill=tk.X, pady=5)  # Added padding between buttons

            self.file_encrypt_button = ttk.Button(self.button_frame, text="File Encryption", command=self.open_file_encryption_window)
            self.file_encrypt_button.pack(fill=tk.X, pady=5)  # Added padding between buttons

            self.key_gen_button = ttk.Button(self.button_frame, text="Key Generator", command=self.open_key_generator_window)
            self.key_gen_button.pack(fill=tk.X, pady=5)  # Added padding between buttons

            self.snake_game_button = ttk.Button(self.button_frame, text="Play Snake", command=start_snake_game)
            self.snake_game_button.pack(fill=tk.X, pady=5)  # Added padding between buttons

            self.quit_button = ttk.Button(self.button_frame, text="Quit", command=self.master.quit)
            self.quit_button.pack(fill=tk.X, pady=5)  # Added padding between buttons

            # Footer Label
            self.footer_label = tk.Label(self.master, text=self.footer_text, font=self.footer_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"], anchor='center')
            self.footer_label.grid(row=2, column=0, columnspan=3, pady=10, sticky='ew')

            # Configure column weights
            self.master.grid_columnconfigure(0, weight=1)
            self.master.grid_columnconfigure(1, weight=1)
            self.master.grid_columnconfigure(2, weight=1)

            self.master.grid_rowconfigure(0, weight=1)
            self.master.grid_rowconfigure(1, weight=1)
            self.master.grid_rowconfigure(2, weight=1)

        except Exception as e:
            print(f"An error occurred in create_layout: {e}")

    def toggle_mode(self):
        self.mode = "light" if self.mode == "dark" else "dark"
        self.apply_color_scheme()
        print("Mode toggled")

    def apply_color_scheme(self):
        colors = self.colors[self.mode]
        self.master.config(bg=colors["bg"])
        for widget in self.master.winfo_children():
            if isinstance(widget, tk.Frame):
                widget.config(bg=colors["bg"])
            if isinstance(widget, tk.Label):
                widget.config(bg=colors["bg"], fg=colors["fg"])
            if isinstance(widget, tk.Text) or isinstance(widget, tk.Entry):
                widget.config(bg=colors["entry_bg"], fg=colors["entry_fg"], insertbackground=colors["entry_fg"])
            if isinstance(widget, ttk.Button):
                widget.config(style='TButton')
                self.style.configure('TButton', background=colors["button_bg"], foreground=colors["button_fg"], bordercolor=colors["border_color"])
                self.style.map('TButton',
                               foreground=[('pressed', colors["button_fg"]), ('active', colors["button_fg"])],
                               background=[('pressed', '!disabled', colors["button_bg"]), ('active', colors["button_bg"])])

    def apply_color_scheme_window(self, window):
        colors = self.colors[self.mode]
        window.config(bg=colors["bg"])
        for widget in window.winfo_children():
            if isinstance(widget, tk.Frame):
                widget.config(bg=colors["bg"])
            if isinstance(widget, tk.Label):
                widget.config(bg=colors["bg"], fg=colors["fg"])
            if isinstance(widget, tk.Text) or isinstance(widget, tk.Entry):
                widget.config(bg=colors["entry_bg"], fg=colors["entry_fg"], insertbackground=colors["entry_fg"])
            if isinstance(widget, ttk.Button):
                widget.config(style='TButton')
                self.style.configure('TButton', background=colors["button_bg"], foreground=colors["button_fg"], bordercolor=colors["border_color"])
                self.style.map('TButton',
                               foreground=[('pressed', colors["button_fg"]), ('active', colors["button_fg"])],
                               background=[('pressed', '!disabled', colors["button_bg"]), ('active', colors["button_bg"])])

    def open_text_encryption_window(self):
        print("Text Encryption window opened.")
        text_window = tk.Toplevel(self.master)
        text_window.title("Text Encryption")
        text_window.geometry("400x400")
        self.apply_color_scheme_window(text_window)

        tk.Label(text_window, text="Enter text to encrypt/decrypt:", font=self.custom_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"]).pack(pady=10)
        text_entry = tk.Text(text_window, height=5, font=self.custom_font, bg=self.colors[self.mode]["entry_bg"], fg=self.colors[self.mode]["entry_fg"], insertbackground=self.colors[self.mode]["entry_fg"])
        text_entry.pack(pady=10)

        tk.Label(text_window, text="Enter encryption key:", font=self.custom_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"]).pack(pady=10)
        key_entry = tk.Entry(text_window, font=self.custom_font, bg=self.colors[self.mode]["entry_bg"], fg=self.colors[self.mode]["entry_fg"], insertbackground=self.colors[self.mode]["entry_fg"])
        key_entry.pack(pady=10)

        result_label = tk.Label(text_window, text="", font=self.custom_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"])
        result_label.pack(pady=10)

        copy_button = tk.Button(text_window, text="Copy", bg=self.colors[self.mode]["button_bg"], fg=self.colors[self.mode]["button_fg"])
        copy_button.pack(pady=10)
        copy_button.pack_forget()  # Initially hide the copy button

        def copy_to_clipboard(text):
            text_window.clipboard_clear()
            text_window.clipboard_append(text)
            messagebox.showinfo("Copied", "Text copied to clipboard")

        def encrypt_text():
            plaintext = text_entry.get("1.0", tk.END).strip()
            key = key_entry.get().strip()
            encrypted_text = vigenere_encrypt(plaintext, key)
            result_label.config(text=f"Encrypted text: {encrypted_text}")
            copy_button.config(command=lambda: copy_to_clipboard(encrypted_text))
            copy_button.pack()  # Show the copy button

        def decrypt_text():
            ciphertext = text_entry.get("1.0", tk.END).strip()
            key = key_entry.get().strip()
            decrypted_text = vigenere_decrypt(ciphertext, key)
            result_label.config(text=f"Decrypted text: {decrypted_text}")
            copy_button.config(command=lambda: copy_to_clipboard(decrypted_text))
            copy_button.pack()  # Show the copy button

        tk.Button(text_window, text="Encrypt", command=encrypt_text, bg=self.colors[self.mode]["button_bg"], fg=self.colors[self.mode]["button_fg"]).pack(side=tk.LEFT, padx=10, pady=10)
        tk.Button(text_window, text="Decrypt", command=decrypt_text, bg=self.colors[self.mode]["button_bg"], fg=self.colors[self.mode]["button_fg"]).pack(side=tk.RIGHT, padx=10, pady=10)

    def open_file_encryption_window(self):
        print("File Encryption window opened.")
        file_window = tk.Toplevel(self.master)
        file_window.title("File Encryption")
        file_window.geometry("400x300")
        self.apply_color_scheme_window(file_window)

        def open_key_window(encrypt, input_file, output_file):
            key_window = tk.Toplevel(file_window)
            key_window.title("Enter Encryption Key")
            key_window.geometry("400x200")
            self.apply_color_scheme_window(key_window)

            tk.Label(key_window, text="Enter encryption key (leave blank to generate):", font=self.custom_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"]).pack(pady=10)
            key_entry = tk.Entry(key_window, font=self.custom_font, bg=self.colors[self.mode]["entry_bg"], fg=self.colors[self.mode]["entry_fg"], insertbackground=self.colors[self.mode]["entry_fg"])
            key_entry.pack(pady=10)

            copy_button = tk.Button(key_window, text="Copy Key", bg=self.colors[self.mode]["button_bg"], fg=self.colors[self.mode]["button_fg"])
            copy_button.pack(pady=10)
            copy_button.pack_forget()  # Initially hide the copy button

            def copy_to_clipboard(text):
                key_window.clipboard_clear()
                key_window.clipboard_append(text)
                messagebox.showinfo("Copied", "Key copied to clipboard")

            def get_or_generate_key():
                key = key_entry.get().strip()
                if not key:
                    key = secrets.token_bytes(32)
                    key_entry.insert(0, key.hex())
                else:
                    key = key.ljust(32)[:32].encode('utf-8')  # Pad or truncate the key to ensure it is 32 bytes long
                copy_button.config(command=lambda: copy_to_clipboard(key.hex()))
                copy_button.pack()  # Show the copy button
                return key

            def start_encryption():
                key = get_or_generate_key()
                if key is None:
                    return
                iv = os.urandom(16)  # Generating a random IV for encryption
                encrypt_file_with_key_iv(input_file, output_file, key, iv)
                messagebox.showinfo("File Encrypted", f"File encrypted successfully.\nKey: {key.hex()}")
                key_window.destroy()

            def start_decryption():
                key = key_entry.get().strip()
                if not key:
                    messagebox.showerror("Error", "Please enter the encryption key used to encrypt the file.")
                    return
                key = key.ljust(32)[:32].encode('utf-8')  # Pad or truncate the key to ensure it is 32 bytes long
                decrypt_file_with_key_iv(input_file, output_file, key)
                messagebox.showinfo("File Decrypted", "File decrypted successfully.")
                key_window.destroy()

            if encrypt:
                tk.Button(key_window, text="Encrypt", command=start_encryption, bg=self.colors[self.mode]["button_bg"], fg=self.colors[self.mode]["button_fg"]).pack(pady=10)
            else:
                tk.Button(key_window, text="Decrypt", command=start_decryption, bg=self.colors[self.mode]["button_bg"], fg=self.colors[self.mode]["button_fg"]).pack(pady=10)

        def encrypt_file():
            input_file = filedialog.askopenfilename(title="Select File to Encrypt")
            if not input_file:
                return
            output_file = filedialog.asksaveasfilename(title="Choose a location to save the encrypted file", defaultextension=".enc", initialfile="Encrypted_File")
            if not output_file:
                return
            open_key_window(encrypt=True, input_file=input_file, output_file=output_file)

        def decrypt_file():
            input_file = filedialog.askopenfilename(title="Select File to Decrypt")
            if not input_file:
                return
            output_file = filedialog.asksaveasfilename(title="Choose a location to save the decrypted file", defaultextension=".dec", initialfile="Decrypted_File")
            if not output_file:
                return
            open_key_window(encrypt=False, input_file=input_file, output_file=output_file)

        def encrypt_file_with_key_iv(input_filename, output_filename, key, iv):
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(algorithms.AES.block_size).padder()

            file_extension = os.path.splitext(input_filename)[1].encode()
            file_extension_len = len(file_extension).to_bytes(1, 'big')

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
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext_with_extension = unpadder.update(padded_plaintext) + unpadder.finalize()

            file_extension_len = plaintext_with_extension[0]
            file_extension = plaintext_with_extension[1:1 + file_extension_len].decode()
            plaintext = plaintext_with_extension[1 + file_extension_len:]

            output_filename_with_extension = os.path.splitext(output_filename)[0] + file_extension

            with open(output_filename_with_extension, 'wb') as f:
                f.write(plaintext)

        tk.Button(file_window, text="Encrypt File", command=encrypt_file, bg=self.colors[self.mode]["button_bg"], fg=self.colors[self.mode]["button_fg"]).pack(padx=10, pady=10)
        tk.Button(file_window, text="Decrypt File", command=decrypt_file, bg=self.colors[self.mode]["button_bg"], fg=self.colors[self.mode]["button_fg"]).pack(padx=10, pady=10)

    def open_key_generator_window(self):
        print("Key Generator window opened.")
        key_window = tk.Toplevel(self.master)
        key_window.title("Key Generator")
        key_window.geometry("400x250")
        self.apply_color_scheme_window(key_window)

        tk.Label(key_window, text="Generated Key:", font=self.custom_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"]).pack(pady=10)
        key_entry = tk.Entry(key_window, font=self.custom_font, width=50, bg=self.colors[self.mode]["entry_bg"], fg=self.colors[self.mode]["entry_fg"], insertbackground=self.colors[self.mode]["entry_fg"])
        key_entry.pack(pady=10)

        copy_button = tk.Button(key_window, text="Copy", bg=self.colors[self.mode]["button_bg"], fg=self.colors[self.mode]["button_fg"])
        copy_button.pack(pady=10)
        copy_button.pack_forget()  # Initially hide the copy button

        def copy_to_clipboard(text):
            key_window.clipboard_clear()
            key_window.clipboard_append(text)
            messagebox.showinfo("Copied", "Key copied to clipboard")

        def generate_key():
            key = secrets.token_bytes(32)  # Generate a 256-bit key
            key_hex = key.hex()
            key_entry.delete(0, tk.END)
            key_entry.insert(0, key_hex)
            copy_button.config(command=lambda: copy_to_clipboard(key_hex))
            copy_button.pack()  # Show the copy button

        tk.Button(key_window, text="Generate Key", command=generate_key, bg=self.colors[self.mode]["button_bg"], fg=self.colors[self.mode]["button_fg"]).pack(pady=10)

    def show_help(self):
        print("Help menu selected.")
        messagebox.showinfo("Help", "This is the help information for PYTHIA.")

# Example usage
def main():
    from platform_specific.windows import platform_specific_setup
    root = tk.Tk()
    root.geometry("600x400")  # Increase default size
    app = PythiaGUI(root, footer_text="Created by ItchySudo. Windows v2.1.1")
    platform_specific_setup(app)
    root.mainloop()

if __name__ == "__main__":
    main()
