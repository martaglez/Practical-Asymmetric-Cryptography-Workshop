#!/usr/bin/env python3
import sys
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

if len(sys.argv) != 4:
    print("Usage: python3 ecc_hybrid_decrypt.py <input_file> <priv_key.pem> <output_file>")
    sys.exit(1)

inp_file, priv_file, out_file = sys.argv[1], sys.argv[2], sys.argv[3]

#  Leer clave privada ECC
with open(priv_file, "rb") as f:
    priv_key = serialization.load_pem_private_key(f.read(), password=None)

with open(inp_file, "rb") as f:
    ephemeral_pub_bytes = f.read(65)  # Punto no comprimido prime256v1
    ciphered_aes_key = f.read(32)
    nonce = f.read(16)
    tag = f.read(16)
    ciphertext = f.read()

#  Reconstruir clave efímera pública
ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ephemeral_pub_bytes)

#  Derivar secreto compartido y descifrar clave AES
shared_secret = priv_key.exchange(ec.ECDH(), ephemeral_pub)
derived_key = shared_secret[:32]
aes_key = bytes(a ^ b for a, b in zip(ciphered_aes_key, derived_key))

#  Descifrar archivo con AES-GCM
cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

#  Guardar resultado
with open(out_file, "wb") as f:
    f.write(plaintext)

print("Decryption done:", out_file)
