import tkinter as tk
from tkinter import font, ttk, messagebox
from core.encryption import vigenere_encrypt, vigenere_decrypt

class EncryptionGUI:
    def __init__(self, master, footer_text):
        self.master = master
        master.title("EISELL - Encrypted Integrity Stealthily Entropic Lattice")

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

        # Create UI components
        self.create_widgets(footer_text)

        # Apply the initial color scheme
        self.apply_color_scheme()

    def create_widgets(self, footer_text):
        self.label = tk.Label(self.master, text="Welcome to EISELL.", font=self.title_font)
        self.label.pack()

        # Create a frame to contain the main buttons
        self.button_frame = tk.Frame(self.master)
        self.button_frame.pack()

        # Configure the style for buttons
        self.style = ttk.Style()
        self.style.theme_use('default')
        self.style.configure('TButton', font=('Consolas', 10))

        # Adjust button width for better usability
        button_width = 20

        # Create main buttons for encrypt, decrypt, and quit
        self.encrypt_button = ttk.Button(self.button_frame, text="Encrypt", command=self.open_encrypt_window, width=button_width)
        self.encrypt_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.decrypt_button = ttk.Button(self.button_frame, text="Decrypt", command=self.open_decrypt_window, width=button_width)
        self.decrypt_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.quit_button = ttk.Button(self.button_frame, text="Quit", command=self.master.quit, width=button_width)
        self.quit_button.pack(side=tk.LEFT, padx=5, pady=5)

        # Create a smaller frame for the toggle button
        self.toggle_frame = tk.Frame(self.master)
        self.toggle_frame.pack()

        # Add the toggle button with a symbol (sun/moon)
        self.toggle_button = ttk.Button(self.toggle_frame, text="☀️", command=self.toggle_mode, width=5)
        self.toggle_button.pack(pady=5)

        # Footer Label
        self.footer_label = tk.Label(self.master, text=footer_text, font=self.footer_font)
        self.footer_label.pack(side=tk.BOTTOM)

    def apply_color_scheme(self):
        colors = self.colors[self.mode]
        self.master.config(bg=colors["bg"])
        self.button_frame.config(bg=colors["bg"])
        self.toggle_frame.config(bg=colors["bg"])
        self.label.config(bg=colors["bg"], fg=colors["fg"])
        self.footer_label.config(bg=colors["bg"], fg=colors["fg"])

        for button in [self.encrypt_button, self.decrypt_button, self.toggle_button, self.quit_button]:
            button.config(style='TButton')
            self.style.configure('TButton', background=colors["button_bg"], foreground=colors["button_fg"], bordercolor=colors["border_color"])
            self.style.map('TButton',
                           foreground=[('pressed', colors["button_fg"]), ('active', colors["button_fg"])],
                           background=[('pressed', '!disabled', colors["button_bg"]), ('active', colors["button_bg"])])

        # Update the symbol on the toggle button
        self.toggle_button.config(text="☀️" if self.mode == "dark" else "🌙")

    def toggle_mode(self):
        self.mode = "light" if self.mode == "dark" else "dark"
        self.apply_color_scheme()

    def open_encrypt_window(self):
        encrypt_window = tk.Toplevel(self.master)
        encrypt_window.title("Encrypt Message")
        self.apply_color_scheme_window(encrypt_window)

        # Create a frame for the entry widgets to ensure background consistency
        entry_frame = tk.Frame(encrypt_window, bg=self.colors[self.mode]["bg"])
        entry_frame.pack(fill=tk.BOTH, expand=True)

        self.plaintext_label = tk.Label(entry_frame, text="Enter the message to encrypt:", font=self.custom_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"])
        self.plaintext_label.pack()

        self.plaintext_entry = tk.Text(entry_frame, width=50, height=5, font=self.custom_font, bg=self.colors[self.mode]["entry_bg"], fg=self.colors[self.mode]["entry_fg"], insertbackground=self.colors[self.mode]["entry_fg"])
        self.plaintext_entry.pack()
        self.plaintext_entry.focus_set()

        self.key_label = tk.Label(entry_frame, text="Enter the encryption key:", font=self.custom_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"])
        self.key_label.pack()

        self.key_entry = tk.Entry(entry_frame, font=self.custom_font, bg=self.colors[self.mode]["entry_bg"], fg=self.colors[self.mode]["entry_fg"], insertbackground=self.colors[self.mode]["entry_fg"])
        self.key_entry.pack()

        self.encrypt_button = ttk.Button(entry_frame, text="Encrypt", command=lambda: self.encrypt_message(encrypt_window))
        self.encrypt_button.pack()

    def encrypt_message(self, encrypt_window):
        plaintext = self.plaintext_entry.get("1.0", tk.END).strip()
        key = self.key_entry.get().upper()

        encrypted_message = vigenere_encrypt(plaintext, key)

        result_label = tk.Label(encrypt_window, text=f"Encrypted message: {encrypted_message}", font=self.custom_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"])
        result_label.pack()

        copy_button = ttk.Button(encrypt_window, text="Copy", command=lambda: self.copy_to_clipboard(encrypted_message))
        copy_button.pack()

        encrypt_window.update_idletasks()
        encrypt_window.geometry(f"{encrypt_window.winfo_reqwidth()}x{encrypt_window.winfo_reqheight()}")

    def open_decrypt_window(self):
        decrypt_window = tk.Toplevel(self.master)
        decrypt_window.title("Decrypt Message")
        self.apply_color_scheme_window(decrypt_window)

        # Create a frame for the entry widgets to ensure background consistency
        entry_frame = tk.Frame(decrypt_window, bg=self.colors[self.mode]["bg"])
        entry_frame.pack(fill=tk.BOTH, expand=True)

        self.ciphertext_label = tk.Label(entry_frame, text="Enter the message to decrypt:", font=self.custom_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"])
        self.ciphertext_label.pack()

        self.ciphertext_entry = tk.Text(entry_frame, width=50, height=5, font=self.custom_font, bg=self.colors[self.mode]["entry_bg"], fg=self.colors[self.mode]["entry_fg"], insertbackground=self.colors[self.mode]["entry_fg"])
        self.ciphertext_entry.pack()
        self.ciphertext_entry.focus_set()

        self.key_label = tk.Label(entry_frame, text="Enter the decryption key:", font=self.custom_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"])
        self.key_label.pack()

        self.key_entry = tk.Entry(entry_frame, font=self.custom_font, bg=self.colors[self.mode]["entry_bg"], fg=self.colors[self.mode]["entry_fg"], insertbackground=self.colors[self.mode]["entry_fg"])
        self.key_entry.pack()

        self.decrypt_button = ttk.Button(entry_frame, text="Decrypt", command=lambda: self.decrypt_message(decrypt_window))
        self.decrypt_button.pack()

    def decrypt_message(self, decrypt_window):
        ciphertext = self.ciphertext_entry.get("1.0", tk.END).strip()
        key = self.key_entry.get().upper()

        decrypted_message = vigenere_decrypt(ciphertext, key)

        result_label = tk.Label(decrypt_window, text=f"Decrypted message: {decrypted_message}", font=self.custom_font, bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"])
        result_label.pack()

        copy_button = ttk.Button(decrypt_window, text="Copy", command=lambda: self.copy_to_clipboard(decrypted_message))
        copy_button.pack()

        decrypt_window.update_idletasks()
        decrypt_window.geometry(f"{decrypt_window.winfo_reqwidth()}x{decrypt_window.winfo_reqheight()}")

    def copy_to_clipboard(self, text):
        self.master.clipboard_clear()
        self.master.clipboard_append(text)

    def apply_color_scheme_window(self, window):
        colors = self.colors[self.mode]
        window.config(bg=colors["bg"])
        for widget in window.winfo_children():
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

        # Update the symbol on the toggle button
        self.toggle_button.config(text="☀️" if self.mode == "dark" else "🌙")
