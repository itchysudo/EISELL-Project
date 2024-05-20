import tkinter as tk
from platform_specific.windows import EncryptionGUI

def main():
    root = tk.Tk()
    root.geometry("500x150")
    app = EncryptionGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
