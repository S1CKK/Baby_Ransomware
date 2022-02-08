import json
from base64 import b64encode,b64decode
from secrets import token_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
from tkinter import *
from tkinter import ttk
root = Tk()
root.title("AES By Art&Chin Team")

# Running
key = get_random_bytes(16)

def encrypt(msg):
    cipher = AES.new(key,AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(msg.encode('ascii'),AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv,'ciphertext':ct})
    return result

def decrypt(json_input):
    try:
        b64 = json.loads(json_input)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key,AES.MODE_CBC,iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('ascii')
    except (ValueError,KeyError):
        return False
    
#Input
message = StringVar()
Label(text="Pleas Enter a message ",padx=10,font=30).grid(row=0,sticky=W)
et1=Entry(font=30,width=30,textvariable=message)
et1.grid(row=0,column=1)

choice = StringVar(value="Encryption or Decryption")
Label(text="What do you want",padx=10,font=30).grid(row=1,sticky=W)
combo=ttk.Combobox(width=30,font=30,textvariable=choice)
combo["values"]=("Encryption","Decryption")
combo.grid(row=1,column=1)


    
#output
Label(text="Result",padx=10,font=30).grid(row=2,sticky=W)
et2=Entry(font=30,width=50)
et2.grid(row=2,column=1)

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
    
Button(text="Run",font=30,width=15,command=calculate).grid(row=3,column=1,sticky=W)
Button(text="Clear",font=30,width=15,command=deleteText).grid(row=3,column=1,sticky=E)


root.mainloop()
