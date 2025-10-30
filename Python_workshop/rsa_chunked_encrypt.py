import sys, time, math
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
 
if len(sys.argv) != 4:
    print("Usage: python3 rsa_chunked_encrypt.py <input_file> <pub_key_pem> <output_file>")
    sys.exit(1)
 
inp, pub_pem, outp = sys.argv[1], sys.argv[2], sys.argv[3]
 
pub = RSA.import_key(open(pub_pem, 'rb').read())
k_bytes = (pub.n.bit_length() + 7) // 8           # modulus size in bytes
hLen = 32                                         # SHA-256
max_pt = k_bytes - 2*hLen - 2                     # OAEP limit
cipher_rsa = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
 
total_in = 0
t0 = time.time()
with open(inp, 'rb') as f_in, open(outp, 'wb') as f_out:
    while True:
        chunk = f_in.read(max_pt)
        if not chunk:
            break
        ct = cipher_rsa.encrypt(chunk)            # length == k_bytes
        f_out.write(ct)
        total_in += len(chunk)
t1 = time.time()
print(f"Encrypted {total_in} bytes in {t1 - t0:.2f}s "
      f"({total_in/1e6:.2f} MB). Ciphertext size: {k_bytes * math.ceil(total_in/max_pt)} bytes.")
