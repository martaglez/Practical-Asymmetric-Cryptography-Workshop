from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
 
key = RSA.import_key(open('student_py.key', 'rb').read())
message = open('secret.txt', 'rb').read()
h = SHA256.new(message)
signature = pkcs1_15.new(key).sign(h)
 
with open('signature.bin', 'wb') as f:
    f.write(signature)
print("Signature saved as signature.bin")
