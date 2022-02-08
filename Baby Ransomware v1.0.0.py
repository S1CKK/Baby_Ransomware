from cgitb import text
from Crypto.PublicKey import RSA
import json
from base64 import b16decode, b16encode, b32decode, b32encode, b64encode,b64decode
from secrets import token_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
from tkinter import *
from tkinter import ttk
root = Tk()
root.title("Baby Ransomware")

rsaKey = RSA.generate(2048)
pubKey = rsaKey.publickey().exportKey("PEM")
priKey = rsaKey.exportKey("PEM")
print(pubKey)
print(priKey)
# Running
key = get_random_bytes(32)

def encrypt(msg):
    cipher = AES.new(key,AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(msg.encode('ascii'),AES.block_size))
    iv = b16encode(cipher.iv).decode('utf-8')
    ct = b32encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv,'ciphertext':ct})
    return result

def decrypt(json_input):
    try:
        b64 = json.loads(json_input)
        iv = b16decode(b64['iv'])
        ct = b32decode(b64['ciphertext'])
        cipher = AES.new(key,AES.MODE_CBC,iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('ascii')
    except (ValueError,KeyError):
        return False
    

#Input
et= Entry(font=30,width=30,textvariable=key)
et.grid(row=0,column=1)

def keyGen():
    et.delete(0,END)
    result = key
    et.insert(0,result)
    
    
Button(text="Gen Key",font=30,width=15,command=keyGen).grid(row=0,column=0,sticky=W)  
message = StringVar()
Label(text="Please Enter a message ",padx=10,font=30).grid(row=1,sticky=W)
et1=Entry(font=30,width=30,textvariable=message)
et1.grid(row=1,column=1)

choice = StringVar(value="Encryption or Decryption")
Label(text="What do you want",padx=10,font=30).grid(row=2,sticky=W)
combo=ttk.Combobox(width=30,font=30,textvariable=choice)
combo["values"]=("Encryption","Decryption")
combo.grid(row=2,column=1)

   
#output
Label(text="Result",padx=10,font=30).grid(row=3,sticky=W)
et2=Entry(font=30,width=50)
et2.grid(row=3,column=1)

def calculate():
    txt=message.get()
    ciphertext = encrypt(txt)
    plaintext = decrypt(txt)
    fx=choice.get()
    
    if fx == "Encryption":
        et2.delete(0,END)
        result = ciphertext
        et2.insert(0,result)
    elif fx =="Decryption":
        et2.delete(0,END)
        result = plaintext
        et2.insert(0,result)
    else:
        pass

def deleteText():
    et1.delete(0,END)
    et2.delete(0,END)
    
Button(text="Run",font=30,width=15,command=calculate).grid(row=4,column=1,sticky=W)
Button(text="Clear",font=30,width=15,command=deleteText).grid(row=4,column=1,sticky=E)


root.mainloop()
