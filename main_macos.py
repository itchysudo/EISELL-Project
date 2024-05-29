import tkinter as tk
from platform_specific.macos import platform_specific_setup

def main():
    root = tk.Tk()
    root.geometry("500x300")
    footer_text = "Created by ItchySudo. macOS v2.1.1"  # Define the footer text for macOS
    app = platform_specific_setup(root, footer_text)
    root.mainloop()

if __name__ == "__main__":
    main()
