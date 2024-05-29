import tkinter as tk
from tkinter import font, ttk, messagebox, filedialog
from PIL import Image, ImageTk  # Import Pillow modules
from core.encryption import vigenere_encrypt, vigenere_decrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import secrets

class PythiaGUI:
    def __init__(self, master, footer_text):
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

        # Create homepage
        self.create_homepage()

        # Apply the initial color scheme
        self.apply_color_scheme()

    def create_homepage(self):
        self.clear_window()

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
        self.label.pack(pady=10)

        # Create a frame to contain the main buttons
        self.button_frame = tk.Frame(self.master, bg=self.colors[self.mode]["bg"])
        self.button_frame.pack(side=tk.LEFT, padx=10, pady=10)

        # Configure the style for buttons
        self.style = ttk.Style()
        self.style.theme_use('default')
        self.style.configure('TButton', font=('Consolas', 10))

        # Create main buttons for text encrypt, file encrypt, and quit
        self.text_encrypt_button = ttk.Button(self.button_frame, text="Text Encryption", command=self.open_text_encryption_window)
        self.text_encrypt_button.pack(fill=tk.X, pady=5)  # Added padding between buttons

        self.file_encrypt_button = ttk.Button(self.button_frame, text="File Encryption", command=self.open_file_encryption_window)
        self.file_encrypt_button.pack(fill=tk.X, pady=5)  # Added padding between buttons

        self.key_gen_button = ttk.Button(self.button_frame, text="Key Generator", command=self.open_key_generator_window)
        self.key_gen_button.pack(fill=tk.X, pady=5)  # Added padding between buttons

        self.quit_button = ttk.Button(self.button_frame, text="Quit", command=self.master.quit)
        self.quit_button.pack(fill=tk.X, pady=5)  # Added padding between buttons

        # Footer Label
        self.footer_label = tk.Label(self.master, text=self.footer_text, font=self.footer_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"])
        self.footer_label.pack(side=tk.BOTTOM)

    def open_text_encryption_window(self):
        self.clear_window()

        entry_frame = tk.Frame(self.master, bg=self.colors[self.mode]["bg"])
        entry_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.plaintext_label = tk.Label(entry_frame, text="Enter the message to encrypt:", font=self.custom_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"])
        self.plaintext_label.pack()

        self.plaintext_entry = tk.Text(entry_frame, width=50, height=5, font=self.custom_font, bg=self.colors[self.mode]["entry_bg"], fg=self.colors[self.mode]["entry_fg"], insertbackground=self.colors[self.mode]["entry_fg"])
        self.plaintext_entry.pack()
        self.plaintext_entry.focus_set()

        self.key_label = tk.Label(entry_frame, text="Enter the encryption key:", font=self.custom_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"])
        self.key_label.pack()

        self.key_entry = tk.Entry(entry_frame, font=self.custom_font, bg=self.colors[self.mode]["entry_bg"], fg=self.colors[self.mode]["entry_fg"], insertbackground=self.colors[self.mode]["entry_fg"])
        self.key_entry.pack()

        self.generate_key_button = ttk.Button(entry_frame, text="Generate Key", command=lambda: self.generate_key_for_entry(self.key_entry))
        self.generate_key_button.pack(pady=5)  # Added padding between buttons

        self.encrypt_button = ttk.Button(entry_frame, text="Encrypt", command=lambda: self.encrypt_message(entry_frame))
        self.encrypt_button.pack(pady=5)  # Added padding between buttons

        self.decrypt_button = ttk.Button(entry_frame, text="Decrypt", command=lambda: self.decrypt_message(entry_frame))
        self.decrypt_button.pack(pady=5)  # Added padding between buttons

        back_button = ttk.Button(entry_frame, text="Back", command=lambda: self.go_home())
        back_button.pack(pady=5)  # Added padding between buttons

    def open_file_encryption_window(self):
        self.clear_window()

        entry_frame = tk.Frame(self.master, bg=self.colors[self.mode]["bg"])
        entry_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        encrypt_button = ttk.Button(entry_frame, text="Encrypt File", command=self.encrypt_file_dialog)
        encrypt_button.pack(pady=5)  # Added padding between buttons

        decrypt_button = ttk.Button(entry_frame, text="Decrypt File", command=self.decrypt_file_dialog)
        decrypt_button.pack(pady=5)  # Added padding between buttons

        back_button = ttk.Button(entry_frame, text="Back", command=lambda: self.go_home())
        back_button.pack(pady=5)  # Added padding between buttons

    def open_key_generator_window(self):
        self.clear_window()

        entry_frame = tk.Frame(self.master, bg=self.colors[self.mode]["bg"])
        entry_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.key_label = tk.Label(entry_frame, text="Generated Key:", font=self.custom_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"])
        self.key_label.pack()

        self.key_entry = tk.Entry(entry_frame, font=self.custom_font, bg=self.colors[self.mode]["entry_bg"], fg=self.colors[self.mode]["entry_fg"], insertbackground=self.colors[self.mode]["entry_fg"])
        self.key_entry.pack()

        self.generate_key_button = ttk.Button(entry_frame, text="Generate Key", command=lambda: self.generate_key_for_entry(self.key_entry))
        self.generate_key_button.pack(pady=5)  # Added padding between buttons

        back_button = ttk.Button(entry_frame, text="Back", command=lambda: self.go_home())
        back_button.pack(pady=5)  # Added padding between buttons

    def go_home(self):
        self.create_homepage()
        self.apply_color_scheme()  # Ensure color scheme is applied when going back to homepage

    def clear_window(self):
        for widget in self.master.winfo_children():
            widget.destroy()

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

    def toggle_mode(self):
        self.mode = "light" if self.mode == "dark" else "dark"
        self.apply_color_scheme()

    def encrypt_message(self, parent_frame):
        plaintext = self.plaintext_entry.get("1.0", tk.END).strip()
        key = self.key_entry.get().upper()
        key = self.ensure_key_length(key)

        encrypted_message = vigenere_encrypt(plaintext, key)

        result_label = tk.Label(parent_frame, text=f"Encrypted message: {encrypted_message}", font=self.custom_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"])
        result_label.pack()

        copy_button = ttk.Button(parent_frame, text="Copy", command=lambda: self.copy_to_clipboard(encrypted_message))
        copy_button.pack(pady=5)  # Added padding between buttons

        parent_frame.update_idletasks()
        parent_frame.geometry(f"{parent_frame.winfo_reqwidth()}x{parent_frame.winfo_reqheight()}")

    def decrypt_message(self, parent_frame):
        ciphertext = self.plaintext_entry.get("1.0", tk.END).strip()
        key = self.key_entry.get().upper()
        key = self.ensure_key_length(key)

        decrypted_message = vigenere_decrypt(ciphertext, key)

        result_label = tk.Label(parent_frame, text=f"Decrypted message: {decrypted_message}", font=self.custom_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"])
        result_label.pack()

        copy_button = ttk.Button(parent_frame, text="Copy", command=lambda: self.copy_to_clipboard(decrypted_message))
        copy_button.pack(pady=5)  # Added padding between buttons

        parent_frame.update_idletasks()
        parent_frame.geometry(f"{parent_frame.winfo_reqwidth()}x{parent_frame.winfo_reqheight()}")

    def copy_to_clipboard(self, text):
        self.master.clipboard_clear()
        self.master.clipboard_append(text)

    def encrypt_file_dialog(self):
        input_filename = filedialog.askopenfilename(title="Select File to Encrypt")
        if not input_filename:
            return

        output_filename = filedialog.asksaveasfilename(title="Save Encrypted File As")
        if not output_filename:
            return

        key = self.get_key_from_user(include_generate_button=True)
        if not key:
            return

        iv = self.generate_iv()
        self.encrypt_file(input_filename, output_filename, key, iv)
        messagebox.showinfo("Success", f"File encrypted successfully.\nKey: {key.decode()}")

    def decrypt_file_dialog(self):
        input_filename = filedialog.askopenfilename(title="Select File to Decrypt")
        if not input_filename:
            return

        output_filename = filedialog.asksaveasfilename(title="Save Decrypted File As")
        if not output_filename:
            return

        key = self.get_key_from_user(include_generate_button=False)
        if not key:
            return

        self.decrypt_file(input_filename, output_filename, key)
        messagebox.showinfo("Success", "File decrypted successfully.")

    def generate_iv(self, iv_size=16):
        return os.urandom(iv_size)

    def encrypt_file(self, input_filename, output_filename, key, iv):
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

    def decrypt_file(self, input_filename, output_filename, key):
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

    def get_key_from_user(self, include_generate_button=True):
        key_window = tk.Toplevel(self.master)
        key_window.title("Enter Key")
        self.apply_color_scheme_window(key_window)

        key_label = tk.Label(key_window, text="Enter the key:", font=self.custom_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"])
        key_label.pack()

        key_entry = tk.Entry(key_window, font=self.custom_font, bg=self.colors[self.mode]["entry_bg"], fg=self.colors[self.mode]["entry_fg"], insertbackground=self.colors[self.mode]["entry_fg"])
        key_entry.pack()

        if include_generate_button:
            generate_key_button = ttk.Button(key_window, text="Generate Key", command=lambda: self.generate_key_for_entry(key_entry))
            generate_key_button.pack(pady=5)  # Added padding between buttons

        key = []

        def on_submit():
            key.append(self.ensure_key_length(key_entry.get().encode()))
            key_window.destroy()

        submit_button = ttk.Button(key_window, text="Submit", command=on_submit)
        submit_button.pack(pady=5)  # Added padding between buttons

        key_window.wait_window()
        return key[0] if key else None

    def generate_key_for_entry(self, entry):
        key = secrets.token_hex(16)  # Generate a random 16-byte key
        entry.delete(0, tk.END)
        entry.insert(0, key)

    def ensure_key_length(self, key, desired_length=32):
        if len(key) < desired_length:
            return key.ljust(desired_length, b'\0')
        elif len(key) > desired_length:
            return key[:desired_length]
        return key

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

    def show_help(self):
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
