def convert_base(m: bytes, initial_base: int, final_base:int) -> bytes:
    num = 0
    pow = 1
    res = b""
    for i in range(len(m)):
        num += m[len(m) - 1 - i]*pow
        pow*=initial_base
    while num>0:
        r = num%final_base
        res += bytes([r])
        num = num//final_base
    return res[::-1]
def group_sub(m1: bytes, m2: bytes) -> bytes:
    res = b""
    for i in range(len(m1)):
        res += bytes([(m1[i]+256-m2[i])%255])
    return res
with open("ciphertext.enc", "rb") as f:
     cipher = f.read()
with open("keyfile", "rb") as f:
    key = f.read()
cipher_255 = convert_base(cipher, 256, 255)
plaintext_255 = group_sub(cipher_255, key)
plaintext = convert_base(plaintext_255, 255, 256)
print(plaintext)