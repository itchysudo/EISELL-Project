import core.encryption_gui

def platform_specific_setup(root, footer_text):
    # Perform any Windows-specific setup here if needed
    return core.encryption_gui.EISELLGUI(root, footer_text)  # Updated to use EISELLGUI
