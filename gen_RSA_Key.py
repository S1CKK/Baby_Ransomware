from Crypto.PublicKey import RSA

key = RSA.generate(2048)
f = open('rsa_key.txt','wb')
f.write(key.publickey().export_key('PEM'))
f.write(key.export_key('PEM'))
f.close()
