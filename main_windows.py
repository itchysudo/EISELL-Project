import tkinter as tk
from core.encryption_gui import EncryptionGUI
from platform_specific.windows import platform_specific_setup

def main():
    root = tk.Tk()
    root.geometry("500x150")
    footer_text = platform_specific_setup()
    app = EncryptionGUI(root, footer_text)
    root.mainloop()

if __name__ == "__main__":
    main()
