import os
def scan_script_security(filepath: str) -> str:
    if not os.path.exists(filepath): return "[!] Error: File not found."
    with open(filepath, 'r') as file: content = file.read()
    if "shell=True" in content: return "[!] Warning: Unsafe code detected!"
    return "[+] Code appears safe. Pending Codex validation."
