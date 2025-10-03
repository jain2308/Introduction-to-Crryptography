from pwn import *
from Crypto.Util.Padding import pad, unpad

HOST = "0.cloud.chals.io"
PORT = 19966

# Uncomment the 'process' line below when you want to test locally, uncomment the 'remote' line below when you want to execute your exploit on the server
# target = process(["python", "./server.py"])
target = remote(HOST, PORT)

def recvuntil(msg):
    resp = target.recvuntil(msg.encode()).decode()
    print(resp)
    return resp

def sendline(msg):
    print(msg)
    target.sendline(msg.encode())

def recvline():
    resp = target.recvline().decode()
    print(resp)
    return resp

def recvall():
    resp = target.recvall().decode()
    print(resp)
    return resp


recvuntil("IV: ")
IV = bytes.fromhex(recvline())

recvuntil("Flag: ")
flag_enc = bytes.fromhex(recvline())


def validate_padding(iv_hex: str, ciphertext_hex: str) -> bool:
    recvuntil("validated:\n")
    sendline(ciphertext_hex)
    recvuntil("IV:\n")
    sendline(iv_hex)
    response = recvline()
    valid_padding = ("Valid Padding!" in response)
    return valid_padding


# ===== YOUR CODE BELOW =====
# The variable IV has the iv (as a bytes object)
# The variable flag_enc has the ciphertext (as a bytes object)
# You can call the function validate_padding(iv_hex: str, ciphertext_hex: str) -> bool which takes in the hex of the iv (str) and hex of the ciphertext (str) and returns True if the corresponding plaintext has valid padding, and return False otherwise (as dictated by the server's response)
c1 = flag_enc[0:16]
c2 = flag_enc[16:32]
flag = b"0"*16
for byte_index in range(15, -1, -1):
    padding = 16 - byte_index
    for i in range(256):
        c_ = b"0"*16
        for j in range(16):
            if j < byte_index:
                c_[j] = c1[j]
            else:
                c_[j] = c1[j] ^ flag[j] ^ padding

        # Set the guess byte
        c_[byte_index] = c1[byte_index] ^ i ^ padding_value
        
        # Send fake block and c2 for validation
        iv_hex = fake_block.hex()
        ciphertext_hex = c2.hex()
        if validate_padding(iv_hex, ciphertext_hex):
            print(f"[+] Found guess {guess:02x} at position {byte_index}")
            # Compute intermediate value
            intermediate[byte_index] = guess ^ padding_value
            # Recover the plaintext byte
            recovered[byte_index] = intermediate[byte_index] ^ c1[byte_index]
            print(f"Recovered byte: {recovered[byte_index]:02x} -> {chr(recovered[byte_index])}")
            break
plaintext = bytes(recovered)
print("\nRecovered plaintext block:")
print(plaintext)
print("As string:")
print(plaintext.decode(errors='ignore'))
# ===== YOUR CODE BELOW =====

target.close()
