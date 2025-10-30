#!/usr/bin/env python3
import sys, json
from cryptography.hazmat.primitives import serialization

def num_info(n):
    return {"dec": n, "bits": n.bit_length(), "hex": hex(n)}

if len(sys.argv) < 2:
    print("Uso: python3 dh_pub_to_json.py <archivo_publico.pem>")
    sys.exit(1)

with open(sys.argv[1], "rb") as f:
    data = f.read()

d = {}

try:
    pub_key = serialization.load_pem_public_key(data)
    pub_numbers = pub_key.public_numbers()  # <- método
    params = pub_numbers.parameter_numbers     # <- atributo

    d = {
        "p": num_info(params.p),
        "g": num_info(params.g),
        "pub": num_info(pub_numbers.y)
    }

except Exception as e:
    print("Error al leer la clave pública:", e)
    sys.exit(1)

print(json.dumps(d, indent=2))
