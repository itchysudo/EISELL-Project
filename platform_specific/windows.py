from core.encryption_gui import PythiaGUI  # Corrected import statement

def platform_specific_setup(root, footer_text):
    # Perform any Windows-specific setup here if needed
    return PythiaGUI(root, footer_text)  # Updated to use PythiaGUI
