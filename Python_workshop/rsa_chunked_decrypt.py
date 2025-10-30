import sys, time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
 
if len(sys.argv) != 4:
    print("Usage: python3 rsa_chunked_decrypt.py <input_file> <priv_key_pem> <output_file>")
    sys.exit(1)
 
inp, priv_pem, outp = sys.argv[1], sys.argv[2], sys.argv[3]
 
priv = RSA.import_key(open(priv_pem, 'rb').read())
k_bytes = (priv.n.bit_length() + 7) // 8          # each RSA ciphertext block size
cipher_rsa = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
 
total_out = 0
t0 = time.time()
with open(inp, 'rb') as f_in, open(outp, 'wb') as f_out:
    while True:
        ct = f_in.read(k_bytes)
        if not ct:
            break
        pt = cipher_rsa.decrypt(ct)
        f_out.write(pt)
        total_out += len(pt)
t1 = time.time()
print(f"Decrypted {total_out} bytes in {t1 - t0:.2f}s ({total_out/1e6:.2f} MB).")
