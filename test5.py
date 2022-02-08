import json
from base64 import b64encode,b64decode
from secrets import token_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes

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

ciphertext = encrypt(input("Enter : "))
plaintext = decrypt(ciphertext)
print(f'Cipher text : {ciphertext}')
print(f'Plaintext text : {plaintext}')