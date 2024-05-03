import random
from Crypto.Cipher import AES
import hashlib
from math import gcd



def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return 1

def generate_private_key(q):
    while True:
        XA = random.randint(1, q - 2)
        if 1 < XA < q:
            return XA

def hash_to_integer(M, q):
    hash_integer = int(hashlib.sha1(str(M).encode()).hexdigest(), 16)
    return hash_integer % q

def compute_el_gamal_signature(M, q, alpha, XA):
    m = hash_to_integer(M, q)

    while True:
        k = random.randint(1, q - 1)
        if 0 < k < q and gcd(k, q - 1) == 1:
            break

    S1 = pow(alpha, k, q)
    k_inverse = mod_inverse(k, q - 1)
    S2 = (m - XA * S1) * k_inverse % (q - 1)
    if S2 < 0:
        S2 += q - 1

    return S1, S2

def mod_pow(base, exponent, modulus):
    result = 1
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent //= 2
    return result
def compute_shared_key(Y, X, q):
    return mod_pow(Y, X, q)
def generate_aes_key(shared_key):
    # Convert the shared key to bytes
    shared_key_bytes = shared_key.to_bytes((shared_key.bit_length() + 7) // 8, 'big')
    sha256 = hashlib.sha256()
    sha256.update(shared_key_bytes)

    # Get the hash value and use it as the AES key
    aes_key= sha256.digest()

    return aes_key

def send_long_value(socket, value):
    try:
        socket.send(str(value).encode())
    except Exception as e:
        print(e)

def send_string(socket, message):
    try:
        socket.send(message.encode())
    except Exception as e:
        print(e)

def receive_long_value(socket):
    try:
        return int(socket.recv(1024).decode())
    except Exception as e:
        print(e)
        return -1

def receive_string(socket):
    try:
        return socket.recv(1024).decode()
    except Exception as e:
        print(e)
        return None

def verify_signature(alpha, M, qGL, YA, S1, S2):
    m = hash_to_integer(M, qGL)

    V1 = mod_pow(alpha, m, qGL)
    V2 = (mod_pow(YA, S1, qGL) * mod_pow(S1, S2, qGL)) % qGL

    return V1 == V2
def encrypt_message(message, aes_key):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    
    padded_message = message.encode().rjust((len(message) + 15) // 16 * 16)
    ciphertext = cipher.encrypt(padded_message)
    return ciphertext

def decrypt_message(ciphertext, aes_key):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    decrypted_message = cipher.decrypt(ciphertext)
    
    unpadded_message = decrypted_message.rstrip(b'\0').decode()
    return unpadded_message

def send_encrypted_message(socket, encrypted_message):
    socket.send(encrypted_message)

def receive_encrypted_message(socket):
    encrypted_message = socket.recv(4096)

    return encrypted_message