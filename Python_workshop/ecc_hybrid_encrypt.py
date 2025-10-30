#!/usr/bin/env python3
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

if len(sys.argv) != 4:
    print("Usage: python3 ecc_hybrid_encrypt.py <input_file> <pub_key.pem> <output_file>")
    sys.exit(1)

inp_file, pub_file, out_file = sys.argv[1], sys.argv[2], sys.argv[3]

#  Leer clave pública ECC
with open(pub_file, "rb") as f:
    pub_key = serialization.load_pem_public_key(f.read())

#  Generar clave AES para cifrar el archivo
aes_key = get_random_bytes(32)  # AES-256
cipher_aes = AES.new(aes_key, AES.MODE_GCM)
with open(inp_file, "rb") as f:
    plaintext = f.read()
ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

#  Cifrar la clave AES con ECC (usando el public key)
# Método: usar ECDH + derivar secreto para AES-ECB temporal
# Esto es simplificado: derivamos un secreto compartido y usamos XOR para "cifrar" la AES key
ephemeral_private = ec.generate_private_key(ec.SECP256R1())
shared_secret = ephemeral_private.exchange(ec.ECDH(), pub_key)
derived_key = shared_secret[:32]  # Tomamos primeros 32 bytes
ciphered_aes_key = bytes(a ^ b for a, b in zip(aes_key, derived_key))

#  Guardar todo en el archivo de salida
with open(out_file, "wb") as f:
    f.write(ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    ))
    f.write(ciphered_aes_key)
    f.write(cipher_aes.nonce)
    f.write(tag)
    f.write(ciphertext)

print("Encryption done:", out_file)
