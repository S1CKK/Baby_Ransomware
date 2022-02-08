from Crypto.Cipher import AES

key = b'1111111111111111'
data=b'art'
cipher = AES.new(key, AES.MODE_EAX)

nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(data)