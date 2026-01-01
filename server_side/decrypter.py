import tkinter as tk
from tkinter import simpledialog

from cryptography.fernet import Fernet

import sys
import os

def write_file(content,path):
    with open(path,'wb') as file:
        file.write(content)

def read_file_content(path):
    with open(path,'rb') as file:
        content = file.read()
    return content

def decrypt_files(cipher,path):
    files = os.listdir(path)
    for file in files:
        new_path = os.path.join(path, file)
        if os.path.isfile(new_path):
            decrypt_file_content(new_path,cipher)
            
        elif os.path.isdir(new_path):
            decrypt_files(cipher,new_path)
            
def decrypt_file_content(path,cipher):
    encrypted_content = read_file_content(path)
    decrypted_content = cipher.decrypt(encrypted_content)
    write_file(decrypted_content,path)

def show_decrypter():
    root = tk.Tk()
    root.withdraw()

    key = simpledialog.askstring(
        title="decrypter",
        prompt="enter the decryption key here:"
    )
    return key

def main():
    show_decrypter
    key = show_decrypter()
    cipher = Fernet(key)
    path = sys.argv[1]
    decrypt_files(cipher,path)

if __name__ == "__main__":
    main()

