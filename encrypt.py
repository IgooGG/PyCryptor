import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

class EncryptApp:
    def __init__(self, root):
        self.root = root
        self.root.title('File Encryptor/Decryptor')
        self.root.geometry('400x300')

        # File selection
        self.file_label = tk.Label(root, text="Selected File: None")
        self.file_label.pack(pady=10)

        self.select_file_btn = tk.Button(root, text="Select File", command=self.select_file)
        self.select_file_btn.pack()

        # Password input
        self.password_label = tk.Label(root, text="Password:")
        self.password_label.pack(pady=5)
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack()

        # Buttons
        self.encrypt_btn = tk.Button(root, text="Encrypt", command=self.encrypt_file)
        self.encrypt_btn.pack(side=tk.LEFT, padx=20, pady=20)

        self.decrypt_btn = tk.Button(root, text="Decrypt", command=self.decrypt_file)
        self.decrypt_btn.pack(side=tk.RIGHT, padx=20, pady=20)

        self.selected_file = None

    def select_file(self):
        self.selected_file = filedialog.askopenfilename()
        if self.selected_file:
            self.file_label.config(text=f"Selected File: {os.path.basename(self.selected_file)}")
        else:
            self.file_label.config(text="Selected File: None")

    def encrypt_file(self):
        password = self.password_entry.get()
        if not self.selected_file:
            messagebox.showerror('Error', 'Please select a file.')
            return
        if not password:
            messagebox.showerror('Error', 'Please enter a password.')
            return
        try:
            encrypt_file_aes(self.selected_file, password)
            messagebox.showinfo('Success', f'File encrypted: {os.path.basename(self.selected_file)}.enc')
        except Exception as e:
            messagebox.showerror('Error', str(e))

    def decrypt_file(self):
        password = self.password_entry.get()
        if not self.selected_file:
            messagebox.showerror('Error', 'Please select a file.')
            return
        if not password:
            messagebox.showerror('Error', 'Please enter a password.')
            return
        if not self.selected_file.endswith('.enc'):
            messagebox.showerror('Error', 'Please select an encrypted file (.enc).')
            return
        try:
            decrypt_file_aes(self.selected_file, password)
            original_path = self.selected_file[:-4]  # Remove .enc extension
            messagebox.showinfo('Success', f'File decrypted: {os.path.basename(original_path)}')
        except Exception as e:
            messagebox.showerror('Error', str(e))

def encrypt_file_aes(file_path, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_CBC)
    with open(file_path, 'rb') as f:
        data = f.read()
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    with open(file_path + '.enc', 'wb') as f:
        f.write(salt + cipher.iv + encrypted_data)
    os.remove(file_path)  # Remove the original unencrypted file

def decrypt_file_aes(file_path, password):
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    original_path = file_path[:-4]
    with open(original_path, 'wb') as f:
        f.write(decrypted_data)
    os.remove(file_path)  # Remove the encrypted file

if __name__ == '__main__':
    root = tk.Tk()
    app = EncryptApp(root)
    root.mainloop()
