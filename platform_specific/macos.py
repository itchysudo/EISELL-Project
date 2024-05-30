import core.encryption_gui

def platform_specific_setup(root, footer_text):
    # Perform any macOS-specific setup here if needed
    return EncryptionGUI(root, footer_text)
