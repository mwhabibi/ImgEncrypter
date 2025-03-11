import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
import os

# === Fungsi Utilitas ===
def load_image(file_path):
    with open(file_path, "rb") as file:
        return file.read()

def save_image(file_path, data):
    with open(file_path, "wb") as file:
        file.write(data)

# === Generate RSA Keys ===
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(data, public_key):
    return public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(encrypted_data, private_key):
    return private_key.decrypt(
        encrypted_data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# === Caesar Cipher (Modifikasi) ===
def caesar_encrypt(data, key):
    key_bytes = key.encode()
    return bytes((byte + key_bytes[i % len(key_bytes)]) % 256 for i, byte in enumerate(data))

def caesar_decrypt(data, key):
    key_bytes = key.encode()
    return bytes((byte - key_bytes[i % len(key_bytes)]) % 256 for i, byte in enumerate(data))

# === Vigenère Cipher ===
def vigenere_encrypt(data, key):
    key_bytes = key.encode()
    return bytes((byte + key_bytes[i % len(key_bytes)]) % 256 for i, byte in enumerate(data))

def vigenere_decrypt(data, key):
    key_bytes = key.encode()
    return bytes((byte - key_bytes[i % len(key_bytes)]) % 256 for i, byte in enumerate(data))

# === Zig-Zag Cipher ===
def zigzag_encrypt(data, rails):
    rail_list = [[] for _ in range(rails)]
    index, step = 0, 1
    for byte in data:
        rail_list[index].append(byte)
        if index == 0:
            step = 1
        elif index == rails - 1:
            step = -1
        index += step
    return bytes(sum(rail_list, []))

def zigzag_decrypt(data, rails):
    if rails <= 1:
        return data
    rail_lengths = [0] * rails
    index, step = 0, 1
    for _ in data:
        rail_lengths[index] += 1
        if index == 0:
            step = 1
        elif index == rails - 1:
            step = -1
        index += step
    parts = []
    start = 0
    for length in rail_lengths:
        parts.append(list(data[start:start + length]))
        start += length
    result = []
    index, step = 0, 1
    for _ in data:
        result.append(parts[index].pop(0))
        if index == 0:
            step = 1
        elif index == rails - 1:
            step = -1
        index += step
    return bytes(result)

# === AES Encryption (CBC Mode) ===
def aes_encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted

def aes_decrypt(encrypted_data, key):
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted) + unpadder.finalize()

# === Setup RSA Keys ===
private_key, public_key = generate_rsa_keys()

def encrypt_image():
    file_path = filedialog.askopenfilename(title="Pilih Gambar")
    if not file_path:
        return
    data = load_image(file_path)
    key_bytes = key_input.get().encode()
    aes_key = key_bytes[:16].ljust(16, b'0')
    encrypted_key = rsa_encrypt(aes_key, public_key)
    encrypted_data = aes_encrypt(zigzag_encrypt(vigenere_encrypt(caesar_encrypt(data, key_input.get()), key_input.get()), 3), aes_key)
    save_image(file_path + ".enc", encrypted_key + encrypted_data)
    messagebox.showinfo("Sukses", "Gambar berhasil dienkripsi!")

def decrypt_image():
    file_path = filedialog.askopenfilename(title="Pilih Gambar Terenkripsi")
    if not file_path:
        return
    data = load_image(file_path)
    try:
        encrypted_key = data[:256]
        encrypted_data = data[256:]
        aes_key = rsa_decrypt(encrypted_key, private_key)
        decrypted_data = caesar_decrypt(vigenere_decrypt(zigzag_decrypt(aes_decrypt(encrypted_data, aes_key), 3), key_input.get()), key_input.get())
        save_image(file_path.replace(".enc", "_decrypted.png"), decrypted_data)
        messagebox.showinfo("Sukses", "Gambar berhasil didekripsi!")
    except Exception as e:
        messagebox.showerror("Error", f"Gagal mendekripsi: {e}")

# === UI Setup ===
root = tk.Tk()
root.title("Aplikasi Enkripsi Gambar Berlapis")
root.geometry("400x200")

tk.Label(root, text="Masukkan Key: ").pack()
key_input = tk.Entry(root, width=40)
key_input.pack()

tk.Button(root, text="Enkripsi Gambar", command=encrypt_image).pack()
tk.Button(root, text="Dekripsi Gambar", command=decrypt_image).pack()

root.mainloop()