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
    
    ct_bytes = cipher.encrypt(pad(original,AES.block_size)) #เข้ารหัสเป็น bytes
    print("ct_bytes = ", ct_bytes)
    
    with open(f'{fname}','wb') as encrypted_file:
        encrypted_file = encrypted_file.write(ct_bytes) #เขียนทับเข้าไปใน file ที่รับมา
    
    iv = b32encode(cipher.iv).decode('utf-8')
    ct = b32encode(ct_bytes).decode('utf-8')
    # fix เพิ่มการแสดง iv,key ทางหน้าจอ
    print(len(cipher.iv)) #เช็ค size iv เฉยๆ
    print("iv(32byte) is : ",cipher.iv)
    print("key(32byte) is : ",key)
    k=b32encode(key).decode('utf-8')
    
    #แสดงไว้เฉยๆ
    print("iv is : ",iv)
    print("ct is : ",ct)
    print("k is : ",k)
    
    # เริ่ม rsa encrypt
    aes_key=json.dumps({'iv':iv,'key':k}).encode('ascii') #เก็บ AESKey ไว้ที่ตัวแปร(aes_key)
    print("LocalKey ก่อนถูกเข้ารหัส: ",aes_key)

    file_out = open("LocalKey.txt", "wb")   #สร้างไฟล์ LocalKey.txt เพื่อเตรียมเขียน AESKey ที่จะถูกเข้ารหัส
    public_key = RSA.import_key(open("receiver.pem").read()) #เก็บ PubKey ไว้ที่ตัวแปร(public_key)

    # Encrypt the secret AES key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(public_key) #แปลง PubKey เพื่อนำไปเข้ารหัส
    cipher_aes = cipher_rsa.encrypt(aes_key) #เข้ารหัส AESKey ด้วย PubKey ที่แปลงมา
    print("LocalKey หลังถูกเข้ารหัส: ",cipher_aes)
    file_out.write(cipher_aes) #เขียน AESKeyที่ถูกเข้ารหัส ลงไปใน LocalKey.txt




def decrypt(fname):
    # เริ่ม decrypt RSA
    file_in = open("LocalKey.txt", "rb") #เปิดไฟล์ LocalKey.txt เพื่อเตรียมอ่าน AESKey ที่ถูกเข้ารหัส
    cipher_aes = file_in.read() #อ่าน AESKey และเก็บไว้ที่ตัวแปร(cipher_aes)

    private_key = RSA.import_key(open("private.pem").read()) #เปิดไฟล์ private.pem เพื่อเก็บ PriKey ไว้ที่ตัวแปร(private_key)

    # Decrypt the secret AES with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key) #แปลง PriKey เพื่อนำไปถอดรหัส
    aes_key = cipher_rsa.decrypt(cipher_aes) #ถอดรหัส AESKey ด้วย PriKey ที่แปลงมา

    #เขียน AESKey ที่ถูกถอดรหัส ลงไปใน LocalKey.txt
    file_out = open("LocalKey.txt", "wb")
    [file_out.write(aes_key)]
    file_out.close()
    
    
    # Print AES,IV 
    print(aes_key.decode("utf-8"))
    
    # แปลง
    try:
        b64 = json.loads(aes_key)
        iv = b32decode(b64['iv'])
        key = b32decode(b64['key'])
        
        with open(f'{fname}','rb') as encrypted_file:
            encrypted = encrypted_file.read()
        
        #decrypted = aes_key.decrypt(encrypted)
        ct = AES.new(key,AES.MODE_CBC,iv)
        print("cipher text = ",ct)
        pt = unpad(ct.decrypt(encrypted), AES.block_size)
        print("pain text = ",pt)
        
        with open(f'{fname}','wb') as decrypted_file:
            decrypted_file.write(pt)
        
        
        #ct = b32decode(b64['ciphertext'])
        
        return pt.decode('ascii')
    except (ValueError,KeyError):
        return False
    

encrypt(input("Enter the file's name : "))
decrypt(input("Enter the file's name : "))
