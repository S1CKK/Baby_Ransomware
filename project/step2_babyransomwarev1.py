from cgitb import text
import base64
from Crypto.PublicKey import RSA
import json
from base64 import b16decode, b16encode, b32decode, b32encode, b64decode
from secrets import token_bytes
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
from tkinter import *
from tkinter import ttk
import os,random,struct
# Running
key = get_random_bytes(32)


# function encrypt
def encrypt(fname):
    cipher = AES.new(key,AES.MODE_CBC)
    
    with open(f'{fname}','rb') as origin_file:
        original = origin_file.read()
    
    ct_bytes = cipher.encrypt(pad(original,AES.block_size))
    
    with open(f'{fname}','wb') as encrypted_file:
        encrypted_file = encrypted_file.write(ct_bytes)
    
    iv = b32encode(cipher.iv).decode('utf-8')
    ct = b32encode(ct_bytes).decode('utf-8')
    # fix เพิ่มการแสดง iv,key ทางหน้าจอ
    print(len(cipher.iv)) #เช็ค size iv เฉยๆ
    print("iv is : ",cipher.iv)
    print("key is : ",key)
    k=b32encode(key).decode('utf-8')
    #print(k)
    
    # เริ่ม rsa encrypt
    data=json.dumps({'iv':iv,'key':k}).encode('ascii')
    file_out = open("LocalKey.txt", "wb")
    #[ file_out.write(data)]

    recipient_key = RSA.import_key(open("receiver.pem").read())
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
    file_out.close()
    
    #result = json.dumps({'iv':iv,'ciphertext':ct})
    #return result




def decrypt(fname):
    # เริ่ม decrypt RSA
    file_in = open("LocalKey.txt", "rb")

    private_key = RSA.import_key(open("private.pem").read())

    enc_session_key, nonce, tag, ciphertext = \
        [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    file_out = open("LocalKey.txt", "wb")
    [ file_out.write(data)]
    file_out.close()
    
    
    # Print AES,IV 
    print(data.decode("utf-8"))
    
    # แปลง
    try:
        b64 = json.loads(data)
        iv = b32decode(b64['iv'])
        aes_key = b32decode(b64['key'])
        
        with open(f'{fname}','rb') as encrypted_file:
            encrypted = encrypted_file.read()
        
        #decrypted = aes_key.decrypt(encrypted)
        cipher = AES.new(aes_key,AES.MODE_CBC,iv)
        pt = unpad(cipher.decrypt(encrypted), AES.block_size)
        
        with open(f'{fname}','wb') as decrypted_file:
            decrypted_file.write(pt)
        
        
        #ct = b32decode(b64['ciphertext'])
        
        return pt.decode('ascii')
    except (ValueError,KeyError):
        return False
    
    

#encrypt(input("Enter the file's name : "))
decrypt(input("Enter the file's name : "))
