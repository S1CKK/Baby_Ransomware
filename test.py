import base64
import hashlib

from Crypto import Random
from Crypto.Cipher import AES

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1])]

class AESAlgorithm:
    def __init__( self):
        pass
    
    def encrypt(self,message,symmetricKey):
        raw = pad(message)
        symmetricKey = hashlib.sha256(symmetricKey.encode('utf-8')).digest()
        iv = Random.new().read( AES.block_size)
        cipher = AES.new( symmetricKey, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))
    
    def decrypt(self,enc,symmetricKey):
        enc = base64.b64decode(enc)
        symmetricKey = hashlib.sha256(symmetricKey.encode('utf-8')).digest()
        iv = enc[:16]
        cipher = AES.new(symmetricKey,AES.MODE_CBC,iv)
        return unpad(cipher.decrypt(enc[16:]))
    
aesAlgorithm = AESAlgorithm()

#Alice
plainText = "Hello World"
symKey1 = "63757843836583645936548364836"
encryptedText = aesAlgorithm.encrypt(plainText,symKey1)
print(encryptedText)

#Bob
symKey2 = "63757843836583645936548364836"
decryptedText = aesAlgorithm.decrypt(encryptedText, symKey2)
print(decryptedText)    