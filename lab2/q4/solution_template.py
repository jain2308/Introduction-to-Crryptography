from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

HOST = "0.cloud.chals.io"
PORT = 23369

# Uncomment the 'process' line below when you want to test locally, uncomment the 'remote' line below when you want to execute your exploit on the server
#target = process(["python", "./server.py"])
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


def send_to_server(input: str) -> tuple[str, str]:
    recvuntil("$ ")
    sendline(input)
    recvuntil("Encrypted Input (hex): ")
    inp_enc = recvline().strip()
    recvuntil("Encrypted Output (hex): ")
    outp_enc = recvline().strip()
    return (inp_enc, outp_enc)


# ===== YOUR CODE BELOW =====
# Use the send_to_server(input) function to send your input (str) to the server
# It returns a 2-tuple of strings as output: the first component being the encrypted input (hex-string), the second component being the encrypted output (hex-string)
outp = send_to_server("a" * 16*51)
inp_enc = outp[0]
print(len(inp_enc))
inp_enc_encoded = bytes.fromhex(inp_enc)
outp1 = send_to_server("!flag")
outp_enc = outp1[1]
out_enc_encoded = bytes.fromhex(outp_enc)
for i in range(len(out_enc_encoded)//16+1):
    input1_block = inp_enc_encoded[16*(30+i):16*(30+i+1)]
    outp_block = out_enc_encoded[16*i:16*(i+1)]
    length = len(outp_block)
    while len(outp_block) < 16:
        outp_block = outp_block + b"0"
    xored_one_time = strxor(input1_block, outp_block)
    our_string = b"a"*16
    print(strxor(xored_one_time, our_string)[:length].decode(), end="")
print("")
# ===== YOUR CODE ABOVE =====

target.close()
