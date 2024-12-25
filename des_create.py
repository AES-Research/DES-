from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom
import binascii

# 生成随机密钥（只生成一次）
key = urandom(8)  # DES密钥长度为8字节
# 将8字节密钥扩展为24字节以适应TripleDES
triple_des_key = key * 3  # 重复密钥以模拟DES

# 打印密钥
print(f"使用的密钥 (8字节): {binascii.hexlify(key).decode('utf-8')}")
print(f"扩展后的 TripleDES 密钥 (24字节): {binascii.hexlify(triple_des_key).decode('utf-8')}\n")

# 生成随机明文
def generate_plaintext():
    plaintext = urandom(8)  # DES数据块长度为8字节
    return plaintext

# DES加密 (使用TripleDES模拟)
def des_encrypt(key, plaintext):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

# 生成10对明文和密文(可根据需求修改）
pairs = []
for _ in range(10):
    plaintext = generate_plaintext()
    ciphertext = des_encrypt(triple_des_key, plaintext)
    pairs.append((binascii.hexlify(plaintext).decode('utf-8'), binascii.hexlify(ciphertext).decode('utf-8')))

# 打印明文和密文对
for i, (pt, ct) in enumerate(pairs, 1):
    print(f"Pair {i}:\nPlaintext: {pt}\nCiphertext: {ct}\n")