import hashlib
def group_sub(m1: bytes, m2: bytes) -> bytes:
    assert len(m1) == len(m2)
    res = b""
    for i in range(len(m1)):
        res += chr((m1[i]-m2[i]+128)%128).encode()
    return res
with open("ciphertext.enc", 'rb') as f:
    Encypted_flag = f.read()
for k in range(128):
    key = chr(k).encode()
    for _ in range(1, len(Encypted_flag)):
        key += chr(hashlib.sha256(key).digest()[0]%128).encode()
    plaintext = group_sub(Encypted_flag, key)
    print(plaintext)