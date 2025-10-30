#!/usr/bin/env python3
import sys, json
from cryptography.hazmat.primitives import serialization

def num_info(n):
    """Devuelve número en decimal, bits y hex."""
    return {
        "dec": n,
        "bits": n.bit_length(),
        "hex": hex(n)
    }

if len(sys.argv) < 2:
    print("Uso: python3 dh_to_json.py <archivo.pem|key>")
    sys.exit(1)

with open(sys.argv[1], "rb") as f:
    data = f.read()

result = {}

try:
    key = serialization.load_pem_private_key(data, password=None)
    priv = key.private_numbers()
    pub = priv.public_numbers
    params = pub.parameter_numbers

    result["type"] = "private"
    result["p"] = num_info(params.p)
    result["g"] = num_info(params.g)
    result["x"] = num_info(priv.x)
    result["pub"] = num_info(pub.y)

except ValueError:
    try:
        # Puede ser pública o solo parámetros
        try:
            pub = serialization.load_pem_public_key(data)
            numbers = pub.public_numbers()
            params = numbers.parameter_numbers()

            result["type"] = "public"
            result["p"] = num_info(params.p)
            result["g"] = num_info(params.g)
            result["pub"] = num_info(numbers.y)

        except Exception:
            key = serialization.load_pem_parameters(data)
            params = key.parameter_numbers()

            result["type"] = "parameters"
            result["p"] = num_info(params.p)
            result["g"] = num_info(params.g)

    except Exception as e:
        print("Error al leer la clave:", e)
        sys.exit(1)

print(json.dumps(result, indent=2))

