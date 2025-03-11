import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64
import os

# === Caesar Cipher ===
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_amount = shift % 26
            new_char = chr(((ord(char.lower()) - 97 + shift_amount) % 26) + 97)
            result += new_char.upper() if char.isupper() else new_char
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# === Vigenère Cipher ===
def vigenere_encrypt(text, key):
    key = key.lower()
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            new_char = chr(((ord(char.lower()) - 97 + shift) % 26) + 97)
            result += new_char.upper() if char.isupper() else new_char
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    key = key.lower()
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            new_char = chr(((ord(char.lower()) - 97 - shift) % 26) + 97)
            result += new_char.upper() if char.isupper() else new_char
            key_index += 1
        else:
            result += char
    return result

# === Zig-Zag Cipher ===
def zigzag_encrypt(text, rails):
    if rails <= 1:
        return text
    rail_list = ["" for _ in range(rails)]
    index, step = 0, 1
    for char in text:
        rail_list[index] += char
        if index == 0:
            step = 1
        elif index == rails - 1:
            step = -1
        index += step
    return "".join(rail_list)

def zigzag_decrypt(text, rails):
    if rails <= 1:
        return text
    rail_lengths = [0] * rails
    index, step = 0, 1
    for _ in text:
        rail_lengths[index] += 1
        if index == 0:
            step = 1
        elif index == rails - 1:
            step = -1
        index += step
    rails_text = [text[sum(rail_lengths[:i]):sum(rail_lengths[:i]) + rail_lengths[i]] for i in range(rails)]
    result = []
    index, step = 0, 1
    for _ in text:
        result.append(rails_text[index][0])
        rails_text[index] = rails_text[index][1:]
        if index == 0:
            step = 1
        elif index == rails - 1:
            step = -1
        index += step
    return "".join(result)

# === AES Encryption ===
def generate_aes_key():
    return os.urandom(16)

def aes_encrypt(text, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    padded_text = text + ' ' * (16 - len(text) % 16)
    encrypted = encryptor.update(padded_text.encode()) + encryptor.finalize()
    return base64.b64encode(encrypted).decode()

import base64

def aes_decrypt(encrypted_text, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    
    # Pastikan Base64 memiliki padding yang benar
    missing_padding = len(encrypted_text) % 4
    if missing_padding:
        encrypted_text += "=" * (4 - missing_padding)
    
    decrypted = decryptor.update(base64.b64decode(encrypted_text)) + decryptor.finalize()
    return decrypted.decode().strip()

# === RSA Encryption ===
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(text, public_key):
    encrypted = public_key.encrypt(
        text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def rsa_decrypt(encrypted_text, private_key):
    decrypted = private_key.decrypt(
        base64.b64decode(encrypted_text),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

# === Tkinter UI ===
def encrypt_text():
    text = input_text.get("1.0", tk.END).strip()
    if not text:
        messagebox.showerror("Error", "Teks tidak boleh kosong!")
        return

    key = generate_aes_key()
    encrypted_caesar = caesar_encrypt(text, 3)
    encrypted_vigenere = vigenere_encrypt(encrypted_caesar, "KEY")
    encrypted_zigzag = zigzag_encrypt(encrypted_vigenere, 3)
    encrypted_aes = aes_encrypt(encrypted_zigzag, key)
    
    private_key, public_key = generate_rsa_keys()
    encrypted_key = rsa_encrypt(base64.b64encode(key).decode(), public_key)

    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, f"AES Key (Save this for decryption): {base64.b64encode(key).decode()}\n")
    output_text.insert(tk.END, f"Encrypted Text: {encrypted_aes}\n")

def decrypt_text():
    encrypted_text = input_text.get("1.0", tk.END).strip()
    aes_key_base64 = aes_key_input.get().strip()
    
    if not encrypted_text or not aes_key_base64:
        messagebox.showerror("Error", "Masukkan teks terenkripsi dan AES Key!")
        return

    try:
        key = base64.b64decode(aes_key_base64 + "===")
    except Exception as e:
        messagebox.showerror("Error", f"Invalid AES Key: {e}")
        return

    decrypted_aes = aes_decrypt(encrypted_text, key)
    decrypted_zigzag = zigzag_decrypt(decrypted_aes, 3)
    decrypted_vigenere = vigenere_decrypt(decrypted_zigzag, "KEY")
    decrypted_caesar = caesar_decrypt(decrypted_vigenere, 3)

    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, f"Decrypted Text: {decrypted_caesar}")

# === UI Setup ===
root = tk.Tk()
root.title("Aplikasi Enkripsi Berlapis")
root.geometry("600x400")

tk.Label(root, text="Input Text:").pack()
input_text = tk.Text(root, height=5, width=50)
input_text.pack()

tk.Label(root, text="AES Key:").pack()
aes_key_input = tk.Entry(root, width=50)
aes_key_input.pack()

tk.Button(root, text="Encrypt", command=encrypt_text).pack()
tk.Button(root, text="Decrypt", command=decrypt_text).pack()

tk.Label(root, text="Output:").pack()
output_text = tk.Text(root, height=5, width=50)
output_text.pack()

root.mainloop()