import tkinter as tk
from platform_specific.windows import platform_specific_setup

def main():
    root = tk.Tk()
    root.geometry("500x300")
    root.minsize(500, 300)  # Set minimum size
    footer_text = "Created by ItchySudo. Windows v2.1.1"  # Define the footer text for Windows
    app = platform_specific_setup(root, footer_text)

    # Center the footer text
    footer_label = tk.Label(root, text=footer_text, font=("Consolas", 8), anchor="center")
    footer_label.pack(side="bottom", fill="x")

    root.mainloop()


if __name__ == "__main__":
    main()
