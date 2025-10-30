key_pub = RSA.import_key(open('student_py_pub.key', 'rb').read())
message = open('secret.txt', 'rb').read()
signature = open('signature.bin', 'rb').read()
h = SHA256.new(message)
try:
    pkcs1_15.new(key_pub).verify(h, signature)
    print("Signature is valid")
except (ValueError, TypeError):
    print("Signature is NOT valid")
