from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import binascii

# Cargar tu clave DH privada
with open('marta_dh.key', 'rb') as f:  # Cambia por tu archivo DH
    data = f.read()

key = serialization.load_pem_private_key(data, password=None)
priv_nums = key.private_numbers()
pub_nums = priv_nums.public_numbers
params = pub_nums.parameter_numbers

print(f"DH prime modulus p size: {params.p.bit_length()} bits")
print(f"DH generator g size: {params.g.bit_length()} bits")
print(f"DH private x size: {priv_nums.x.bit_length()} bits")
print(f"DH public y size: {pub_nums.y.bit_length()} bits\n")

# Cargar y mostrar AES key
for fname in ['aes_256.key']:
    with open(fname,'rb') as f:
        k = f.read()
    print(f"{fname}: {len(k)} bytes ({len(k)*8} bits)")
    print(f" hex: {binascii.hexlify(k).decode()}\n")
