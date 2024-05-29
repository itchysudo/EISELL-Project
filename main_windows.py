import os
print("Current Working Directory:", os.getcwd())

import tkinter as tk
from platform_specific.windows import platform_specific_setup

def main():
    try:
        root = tk.Tk()
        root.geometry("500x300")
        root.minsize(500, 300)  # Set minimum size
        footer_text = "Created by ItchySudo. Windows v2.1.1"  # Define the footer text for Windows
        print("Initializing platform-specific setup...")
        app = platform_specific_setup(root, footer_text)
        print("Platform-specific setup complete.")

        print("Running main loop")
        root.mainloop()
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
