import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
 
if len(sys.argv) < 4:
    print("Usage: python3 hybrid_decrypt_file.py <input> <priv_key_pem> <output>")
    sys.exit(1)
 
inp, privkey_path, outp = sys.argv[1], sys.argv[2], sys.argv[3]
 
rsa_key = RSA.import_key(open(privkey_path, 'rb').read())
with open(inp, 'rb') as f:
    nonce = f.read(16)
    tag = f.read(16)
    enc_aes_key = f.read(256)  # 2048-bit RSA -> 256 bytes
    ciphertext = f.read()
 
cipher_rsa = PKCS1_OAEP.new(rsa_key)
aes_key = cipher_rsa.decrypt(enc_aes_key)
 
cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)
 
with open(outp, 'wb') as f:
    f.write(data)
print("Wrote:", outp)
