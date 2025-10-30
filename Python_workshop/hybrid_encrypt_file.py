import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
 
if len(sys.argv) < 4:
    print("Usage: python3 hybrid_encrypt_file.py <input> <pub_key_pem> <output>")
    sys.exit(1)
 
inp, pubkey_path, outp = sys.argv[1], sys.argv[2], sys.argv[3]
 
data = open(inp, 'rb').read()
rsa_key = RSA.import_key(open(pubkey_path, 'rb').read())
 
aes_key = get_random_bytes(32)  # 256-bit AES
cipher_aes = AES.new(aes_key, AES.MODE_GCM)
ciphertext, tag = cipher_aes.encrypt_and_digest(data)
 
cipher_rsa = PKCS1_OAEP.new(rsa_key)
enc_aes_key = cipher_rsa.encrypt(aes_key)
 
with open(outp, 'wb') as f:
    for x in (cipher_aes.nonce, tag, enc_aes_key, ciphertext):
        f.write(x)
print("Wrote:", outp)
