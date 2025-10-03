from Crypto.Util.strxor import strxor
with open("ciphertext1.enc", 'rb') as f:
    Flag = f.read()
with open("ciphertext2.enc", 'rb') as f:
    Msg = f.read()
XORED = strxor(Flag, Msg)
flag = b"Cryptanalysis frequently involves statistical attacks"
flag_padded = flag.ljust(len(Flag), b'\x00')
new = strxor(XORED, flag_padded)
print(len(flag))
print(len(Flag))
print(XORED)
print(new)
