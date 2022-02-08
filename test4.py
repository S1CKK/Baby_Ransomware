from Crypto.Cipher import AES

key = b'11111111111'
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
plaintext = cipher.decrypt(ciphertext)
try:
     cipher.verify(tag)
     print("The message is authentic:", plaintext)
except ValueError:
     print("Key incorrect or message corrupted")