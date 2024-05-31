import tkinter as tk
from tkinter import font, ttk, messagebox, filedialog
from PIL import Image, ImageTk
from core.encryption import vigenere_encrypt, vigenere_decrypt, encrypt_file_with_key_iv, decrypt_file_with_key_iv
from core.snake_game import start_snake_game
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import secrets
import hashlib
import random


class EISELLGUI:
    def __init__(self, master, footer_text):
        try:
            self.master = master
            self.footer_text = footer_text
            master.title("EISELL - Python Encryption Application")
            master.geometry("800x600")
            master.minsize(800, 600)

            # Initialize mode
            self.mode = "dark"

            # Set fonts
            self.custom_font = font.Font(family="Consolas", size=12)
            self.title_font = font.Font(family="Consolas", size=24, weight="bold")
            self.footer_font = font.Font(family="Consolas", size=8)

            # Define color schemes
            self.colors = {
                "light": {"bg": "#ffffff", "fg": "#000000", "button_bg": "#eeeeee", "button_fg": "#000000",
                          "entry_bg": "#ffffff", "entry_fg": "#000000", "border_color": "#cccccc"},
                "dark": {"bg": "#333333", "fg": "#ffffff", "button_bg": "#555555", "button_fg": "#ffffff",
                         "entry_bg": "#000000", "entry_fg": "#ffffff", "border_color": "#333333"}
            }

            # Configure button styles
            self.style = ttk.Style()
            self.style.theme_use('default')
            self.style.configure('TButton', font=('Consolas', 12), padding=10)

            # Load icons
            self.icons = self.load_icons()

            # Create the layout
            self.create_layout()

            # Apply the initial color scheme
            self.apply_color_scheme()

            # Start the binary code animation
            self.binary_code_animation()

            print("EISELLGUI initialized successfully.")
        except Exception as e:
            print(f"An error occurred in EISELLGUI initialization: {e}")

    def load_icons(self):
        icons = {}
        try:
            icons["encryption"] = ImageTk.PhotoImage(Image.open("icons/lock.png").resize((20, 20)))
            icons["generators"] = ImageTk.PhotoImage(Image.open("icons/gear.png").resize((20, 20)))
            icons["break"] = ImageTk.PhotoImage(Image.open("icons/coffee.png").resize((20, 20)))
            icons["quit"] = ImageTk.PhotoImage(Image.open("icons/power.png").resize((20, 20)))
        except FileNotFoundError as e:
            print(f"An icon file is missing: {e}")
        return icons

    def create_layout(self):
        try:
            # Main frame
            self.main_frame = tk.Frame(self.master, bg=self.colors[self.mode]["bg"])
            self.main_frame.pack(fill=tk.BOTH, expand=True)

            # Binary animation canvas (packed first to stay at the back)
            self.binary_canvas = tk.Canvas(self.main_frame, bg=self.colors[self.mode]["bg"], highlightthickness=0)
            self.binary_canvas.pack(fill=tk.BOTH, expand=True)

            # Content frame
            self.content_frame = tk.Frame(self.main_frame, bg=self.colors[self.mode]["bg"])
            self.content_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

            # Create a menu bar
            menubar = tk.Menu(self.master)
            self.master.config(menu=menubar)

            # Add Help menu
            help_menu = tk.Menu(menubar, tearoff=0)
            menubar.add_cascade(label="Help", menu=help_menu)
            help_menu.add_command(label="Help", command=self.show_help)

            # Add Toggle mode menu
            menubar.add_command(label="Toggle Mode", command=self.toggle_mode)

            # Create main menu
            self.create_main_menu()

            # Footer Label
            self.footer_label = tk.Label(self.master, text=self.footer_text, font=self.footer_font,
                                         bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"],
                                         anchor='center')
            self.footer_label.pack(side=tk.BOTTOM, fill=tk.X)

        except Exception as e:
            print(f"An error occurred in create_layout: {e}")

    def create_main_menu(self):
        self.clear_frame(self.content_frame)

        # Title Label
        title_label = tk.Label(self.content_frame, text="Welcome to EISELL.", font=self.title_font,
                               bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"])
        title_label.pack(pady=20)

        # Main buttons frame
        button_frame = tk.Frame(self.content_frame, bg=self.colors[self.mode]["bg"])
        button_frame.pack(pady=40)

        # Create buttons with icons and styles
        self.create_button(button_frame, "Encryption", self.open_encryption_menu, self.icons.get("encryption")).pack(
            fill=tk.X, pady=10)
        self.create_button(button_frame, "Generators", self.open_generators_menu, self.icons.get("generators")).pack(
            fill=tk.X, pady=10)
        self.create_button(button_frame, "Take a Break", self.open_take_a_break_menu, self.icons.get("break")).pack(
            fill=tk.X, pady=10)
        self.create_button(button_frame, "Quit", self.master.quit, self.icons.get("quit")).pack(fill=tk.X, pady=10)

    def create_button(self, frame, text, command, icon=None):
        button = tk.Button(frame, text=f"  {text}", command=command, font=('Consolas', 14), image=icon,
                           compound=tk.LEFT, padx=10, pady=10)
        button.configure(bg=self.colors[self.mode]["button_bg"], fg=self.colors[self.mode]["button_fg"],
                         activebackground=self.colors[self.mode]["button_bg"],
                         activeforeground=self.colors[self.mode]["button_fg"])
        button.bind("<Enter>",
                    lambda e: button.config(bg=self.colors[self.mode]["button_fg"], fg=self.colors[self.mode]["bg"]))
        button.bind("<Leave>", lambda e: button.config(bg=self.colors[self.mode]["button_bg"],
                                                       fg=self.colors[self.mode]["button_fg"]))
        return button

    def clear_frame(self, frame):
        for widget in frame.winfo_children():
            widget.destroy()

    def add_back_button(self, frame, command):
        back_arrow = u"\u2190"  # Unicode for left arrow
        back_button = tk.Button(frame, text=back_arrow, font=("Consolas", 16), command=command,
                                bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"], borderwidth=0)
        back_button.pack(anchor='ne', padx=10, pady=10)

    def toggle_mode(self):
        self.mode = "light" if self.mode == "dark" else "dark"
        self.apply_color_scheme()
        print("Mode toggled")

    def apply_color_scheme(self):
        colors = self.colors[self.mode]
        self.master.config(bg=colors["bg"])
        for widget in self.master.winfo_children():
            if isinstance(widget, tk.Frame):
                self.apply_color_scheme_frame(widget)
            if isinstance(widget, tk.Label):
                widget.config(bg=colors["bg"], fg=colors["fg"])
            if isinstance(widget, tk.Text) or isinstance(widget, tk.Entry):
                widget.config(bg=colors["entry_bg"], fg=colors["entry_fg"], insertbackground=colors["entry_fg"])
            if isinstance(widget, ttk.Button):
                widget.config(style='TButton')
                self.style.configure('TButton', background=colors["button_bg"], foreground=colors["button_fg"],
                                     bordercolor=colors["border_color"])
                self.style.map('TButton',
                               foreground=[('pressed', colors["button_fg"]), ('active', colors["button_fg"])],
                               background=[('pressed', '!disabled', colors["button_bg"]),
                                           ('active', colors["button_bg"])])

    def apply_color_scheme_frame(self, frame):
        colors = self.colors[self.mode]
        for widget in frame.winfo_children():
            if isinstance(widget, tk.Frame):
                self.apply_color_scheme_frame(widget)
            elif isinstance(widget, tk.Label):
                widget.config(bg=colors["bg"], fg=colors["fg"])
            elif isinstance(widget, tk.Text) or isinstance(widget, tk.Entry):
                widget.config(bg=colors["entry_bg"], fg=colors["entry_fg"], insertbackground=colors["entry_fg"])
            elif isinstance(widget, ttk.Button):
                widget.config(style='TButton')
                self.style.configure('TButton', background=colors["button_bg"], foreground=colors["button_fg"],
                                     bordercolor=colors["border_color"])
                self.style.map('TButton',
                               foreground=[('pressed', colors["button_fg"]), ('active', colors["button_fg"])],
                               background=[('pressed', '!disabled', colors["button_bg"]),
                                           ('active', colors["button_bg"])])

    def binary_code_animation(self):
        self.binary_items = [self.binary_canvas.create_text(random.randint(0, 800), random.randint(-600, 0),
                                                            text=random.choice(["0", "1"]), font=("Consolas", 12),
                                                            fill=self.colors[self.mode]["fg"]) for _ in range(50)]
        self.animate_binary_code()

    def animate_binary_code(self):
        for item in self.binary_items:
            x, y = self.binary_canvas.coords(item)
            if y >= 600:
                y = random.randint(-600, 0)
                x = random.randint(0, 800)
            self.binary_canvas.coords(item, x, y + 5)
        self.binary_canvas.after(100, self.animate_binary_code)

    def open_encryption_menu(self):
        self.clear_frame(self.content_frame)
        self.add_back_button(self.content_frame, self.create_main_menu)

        label = tk.Label(self.content_frame, text="Encryption", font=self.title_font, bg=self.colors[self.mode]["bg"],
                         fg=self.colors[self.mode]["fg"])
        label.pack(pady=10)

        button_frame = tk.Frame(self.content_frame, bg=self.colors[self.mode]["bg"])
        button_frame.pack(pady=20)

        tk.Button(button_frame, text="Text Encryption", command=self.open_text_encryption_window,
                  bg=self.colors[self.mode]["button_bg"], fg=self.colors[self.mode]["button_fg"]).pack(padx=10, pady=10)
        tk.Button(button_frame, text="File Encryption", command=self.open_file_encryption_window,
                  bg=self.colors[self.mode]["button_bg"], fg=self.colors[self.mode]["button_fg"]).pack(padx=10, pady=10)

    def open_generators_menu(self):
        self.clear_frame(self.content_frame)
        self.add_back_button(self.content_frame, self.create_main_menu)

        label = tk.Label(self.content_frame, text="Generators", font=self.title_font, bg=self.colors[self.mode]["bg"],
                         fg=self.colors[self.mode]["fg"])
        label.pack(pady=10)

        button_frame = tk.Frame(self.content_frame, bg=self.colors[self.mode]["bg"])
        button_frame.pack(pady=20)

        tk.Button(button_frame, text="Key Generator", command=self.open_key_generator_window,
                  bg=self.colors[self.mode]["button_bg"], fg=self.colors[self.mode]["button_fg"]).pack(padx=10, pady=10)

    def open_take_a_break_menu(self):
        self.clear_frame(self.content_frame)
        self.add_back_button(self.content_frame, self.create_main_menu)

        label = tk.Label(self.content_frame, text="Take a Break", font=self.title_font, bg=self.colors[self.mode]["bg"],
                         fg=self.colors[self.mode]["fg"])
        label.pack(pady=10)

        button_frame = tk.Frame(self.content_frame, bg=self.colors[self.mode]["bg"])
        button_frame.pack(pady=20)

        tk.Button(button_frame, text="Play Snake", command=start_snake_game, bg=self.colors[self.mode]["button_bg"],
                  fg=self.colors[self.mode]["button_fg"]).pack(padx=10, pady=10)

    def open_text_encryption_window(self):
        self.clear_frame(self.content_frame)
        self.add_back_button(self.content_frame, self.open_encryption_menu)

        label = tk.Label(self.content_frame, text="Text Encryption", font=self.title_font,
                         bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"])
        label.pack(pady=10)

        entry_frame = tk.Frame(self.content_frame, bg=self.colors[self.mode]["bg"])
        entry_frame.pack(pady=20)

        tk.Label(entry_frame, text="Enter text to encrypt/decrypt:", font=self.custom_font,
                 bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"]).pack(pady=10)
        text_entry = tk.Text(entry_frame, height=5, font=self.custom_font, bg=self.colors[self.mode]["entry_bg"],
                             fg=self.colors[self.mode]["entry_fg"], insertbackground=self.colors[self.mode]["entry_fg"])
        text_entry.pack(pady=10)

        tk.Label(entry_frame, text="Enter encryption key:", font=self.custom_font, bg=self.colors[self.mode]["bg"],
                 fg=self.colors[self.mode]["fg"]).pack(pady=10)
        key_entry = tk.Entry(entry_frame, font=self.custom_font, bg=self.colors[self.mode]["entry_bg"],
                             fg=self.colors[self.mode]["entry_fg"], insertbackground=self.colors[self.mode]["entry_fg"])
        key_entry.pack(pady=10)

        result_label = tk.Label(entry_frame, text="", font=self.custom_font, bg=self.colors[self.mode]["bg"],
                                fg=self.colors[self.mode]["fg"])
        result_label.pack(pady=10)

        copy_button = tk.Button(entry_frame, text="Copy", bg=self.colors[self.mode]["button_bg"],
                                fg=self.colors[self.mode]["button_fg"])
        copy_button.pack(pady=10)
        copy_button.pack_forget()

        def copy_to_clipboard(text):
            self.master.clipboard_clear()
            self.master.clipboard_append(text)
            messagebox.showinfo("Copied", "Text copied to clipboard")

        def encrypt_text():
            plaintext = text_entry.get("1.0", tk.END).strip()
            key = key_entry.get().strip()
            encrypted_text = vigenere_encrypt(plaintext, key)
            result_label.config(text=f"Encrypted text: {encrypted_text}")
            copy_button.config(command=lambda: copy_to_clipboard(encrypted_text))
            copy_button.pack()

        def decrypt_text():
            ciphertext = text_entry.get("1.0", tk.END).strip()
            key = key_entry.get().strip()
            decrypted_text = vigenere_decrypt(ciphertext, key)
            result_label.config(text=f"Decrypted text: {decrypted_text}")
            copy_button.config(command=lambda: copy_to_clipboard(decrypted_text))
            copy_button.pack()

        tk.Button(entry_frame, text="Encrypt", command=encrypt_text, bg=self.colors[self.mode]["button_bg"],
                  fg=self.colors[self.mode]["button_fg"]).pack(side=tk.LEFT, padx=10, pady=10)
        tk.Button(entry_frame, text="Decrypt", command=decrypt_text, bg=self.colors[self.mode]["button_bg"],
                  fg=self.colors[self.mode]["button_fg"]).pack(side=tk.RIGHT, padx=10, pady=10)

    def open_file_encryption_window(self):
        self.clear_frame(self.content_frame)
        self.add_back_button(self.content_frame, self.open_encryption_menu)

        label = tk.Label(self.content_frame, text="File Encryption", font=self.title_font,
                         bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"])
        label.pack(pady=10)

        entry_frame = tk.Frame(self.content_frame, bg=self.colors[self.mode]["bg"])
        entry_frame.pack(pady=20)

        def open_key_window(encrypt, input_file, output_file):
            self.clear_frame(self.content_frame)
            self.add_back_button(self.content_frame, self.open_file_encryption_window)
            key_frame = tk.Frame(self.content_frame, bg=self.colors[self.mode]["bg"])
            key_frame.pack(pady=20)

            tk.Label(key_frame, text="Enter encryption key (leave blank to generate):", font=self.custom_font,
                     bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"]).pack(pady=10)
            key_entry = tk.Entry(key_frame, font=self.custom_font, bg=self.colors[self.mode]["entry_bg"],
                                 fg=self.colors[self.mode]["entry_fg"],
                                 insertbackground=self.colors[self.mode]["entry_fg"])
            key_entry.pack(pady=10)

            copy_button = tk.Button(key_frame, text="Copy Key", bg=self.colors[self.mode]["button_bg"],
                                    fg=self.colors[self.mode]["button_fg"])
            copy_button.pack(pady=10)
            copy_button.pack_forget()

            def copy_to_clipboard(text):
                self.master.clipboard_clear()
                self.master.clipboard_append(text)
                messagebox.showinfo("Copied", "Key copied to clipboard")

            def get_or_generate_key():
                key = key_entry.get().strip()
                if not key:
                    key = secrets.token_bytes(32)
                    key_entry.insert(0, key.hex())
                else:
                    key = hashlib.sha256(key.encode()).digest()
                copy_button.config(command=lambda: copy_to_clipboard(key.hex()))
                copy_button.pack()
                return key

            def start_encryption():
                key = get_or_generate_key()
                if key is None:
                    return
                iv = os.urandom(16)

                def encryption_success_callback():
                    encrypt_file_with_key_iv(input_file, output_file, key, iv)
                    messagebox.showinfo("File Encrypted",
                                        "File encrypted successfully. Please make sure to keep a copy of the key or the encrypted document will be inaccessible.")

                self.show_loading_bar(self.content_frame, encryption_success_callback)

            def start_decryption():
                key = key_entry.get().strip()
                if not key:
                    messagebox.showerror("Error", "Please enter the encryption key used to encrypt the file.")
                    return
                key = hashlib.sha256(key.encode()).digest()

                def decryption_success_callback():
                    decrypt_file_with_key_iv(input_file, output_file, key)
                    messagebox.showinfo("File Decrypted", "File decrypted successfully.")

                self.show_loading_bar(self.content_frame, decryption_success_callback)

            if encrypt:
                tk.Button(key_frame, text="Encrypt", command=start_encryption, bg=self.colors[self.mode]["button_bg"],
                          fg=self.colors[self.mode]["button_fg"]).pack(pady=10)
            else:
                tk.Button(key_frame, text="Decrypt", command=start_decryption, bg=self.colors[self.mode]["button_bg"],
                          fg=self.colors[self.mode]["button_fg"]).pack(pady=10)

        def encrypt_file():
            input_file = filedialog.askopenfilename(title="Select File to Encrypt")
            if not input_file:
                return
            output_file = filedialog.asksaveasfilename(title="Choose a location to save the encrypted file",
                                                       defaultextension=".enc", initialfile="Encrypted_File")
            if not output_file:
                return
            open_key_window(encrypt=True, input_file=input_file, output_file=output_file)

        def decrypt_file():
            input_file = filedialog.askopenfilename(title="Select File to Decrypt")
            if not input_file:
                return
            output_file = filedialog.asksaveasfilename(title="Choose a location to save the decrypted file",
                                                       defaultextension=".dec", initialfile="Decrypted_File")
            if not output_file:
                return
            open_key_window(encrypt=False, input_file=input_file, output_file=output_file)

        tk.Button(entry_frame, text="Encrypt File", command=encrypt_file, bg=self.colors[self.mode]["button_bg"],
                  fg=self.colors[self.mode]["button_fg"]).pack(padx=10, pady=10)
        tk.Button(entry_frame, text="Decrypt File", command=decrypt_file, bg=self.colors[self.mode]["button_bg"],
                  fg=self.colors[self.mode]["button_fg"]).pack(padx=10, pady=10)

    def show_loading_bar(self, window, callback):
        loading_window = tk.Toplevel(window)
        loading_window.title("Processing")
        loading_window.geometry("300x100")
        self.apply_color_scheme_window(loading_window)

        progress = ttk.Progressbar(loading_window, orient="horizontal", length=200, mode="determinate", maximum=100)
        progress.pack(pady=20)

        def update_progress(value):
            if value > 100:
                loading_window.destroy()
                callback()
            else:
                progress['value'] = value
                loading_window.after(50, update_progress, value + 2)

        update_progress(0)

    def open_key_generator_window(self):
        self.clear_frame(self.content_frame)
        self.add_back_button(self.content_frame, self.open_generators_menu)

        label = tk.Label(self.content_frame, text="Key Generator", font=self.title_font,
                         bg=self.colors[self.mode]["bg"], fg=self.colors[self.mode]["fg"])
        label.pack(pady=10)

        entry_frame = tk.Frame(self.content_frame, bg=self.colors[self.mode]["bg"])
        entry_frame.pack(pady=20)

        tk.Label(entry_frame, text="Generated Key:", font=self.custom_font, bg=self.colors[self.mode]["bg"],
                 fg=self.colors[self.mode]["fg"]).pack(pady=10)
        key_entry = tk.Entry(entry_frame, font=self.custom_font, width=50, bg=self.colors[self.mode]["entry_bg"],
                             fg=self.colors[self.mode]["entry_fg"], insertbackground=self.colors[self.mode]["entry_fg"])
        key_entry.pack(pady=10)

        copy_button = tk.Button(entry_frame, text="Copy", bg=self.colors[self.mode]["button_bg"],
                                fg=self.colors[self.mode]["button_fg"])
        copy_button.pack(pady=10)
        copy_button.pack_forget()

        def copy_to_clipboard(text):
            self.master.clipboard_clear()
            self.master.clipboard_append(text)
            messagebox.showinfo("Copied", "Key copied to clipboard")

        def generate_key():
            key = secrets.token_bytes(32)
            key_hex = key.hex()
            key_entry.delete(0, tk.END)
            key_entry.insert(0, key_hex)
            copy_button.config(command=lambda: copy_to_clipboard(key_hex))
            copy_button.pack()

        tk.Button(entry_frame, text="Generate Key", command=generate_key, bg=self.colors[self.mode]["button_bg"],
                  fg=self.colors[self.mode]["button_fg"]).pack(pady=10)

    def load_image(self):
        image_path = filedialog.askopenfilename(title="Select an image")
        if image_path:
            img = Image.open(image_path)
            img = img.resize((100, 100))
            img_tk = ImageTk.PhotoImage(img)
            label = tk.Label(self.master, image=img_tk)
            label.image = img_tk
            label.pack()

    def show_help(self):
        print("Help menu selected.")
        messagebox.showinfo("Help", "This is the help information for EISELL.")

    def apply_color_scheme_window(self, window):
        colors = self.colors[self.mode]
        window.config(bg=colors["bg"])
        for widget in window.winfo_children():
            if isinstance(widget, tk.Frame):
                self.apply_color_scheme_frame(widget)
            elif isinstance(widget, tk.Label):
                widget.config(bg=colors["bg"], fg=colors["fg"])
            elif isinstance(widget, tk.Text) or isinstance(widget, tk.Entry):
                widget.config(bg=colors["entry_bg"], fg=colors["entry_fg"], insertbackground=colors["entry_fg"])
            elif isinstance(widget, ttk.Button):
                widget.config(style='TButton')
                self.style.configure('TButton', background=colors["button_bg"], foreground=colors["button_fg"],
                                     bordercolor=colors["border_color"])
                self.style.map('TButton',
                               foreground=[('pressed', colors["button_fg"]), ('active', colors["button_fg"])],
                               background=[('pressed', '!disabled', colors["button_bg"]),
                                           ('active', colors["button_bg"])])
            else:
                widget.config(bg=colors["bg"], fg=colors["fg"])


if __name__ == "__main__":
    from platform_specific.windows import platform_specific_setup

    root = tk.Tk()
    root.geometry("800x600")
    app = EISELLGUI(root, footer_text="Created by ItchySudo. Windows v2.1.1")
    platform_specific_setup(app)
    root.mainloop()
