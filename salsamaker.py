import os
import struct

def rotate(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def salsa20_g(key, nonce, counter):
    # Unpack the key (32 bytes -> 8 longs) and nonce (8 bytes -> 2 longs)
    k = struct.unpack('<8L', key)  # 8 * 4 bytes = 32 bytes
    n = struct.unpack('<2L', nonce)  # 2 * 4 bytes = 8 bytes

    # Initialize the working variables with constants
    constants = [
        0x61707865,  # "expa"
        0x3320646e,  # "nd  "
        0x79622d32,  # "3"
        0x6b206574   # "2"
    ]
    
    # Create the x list in the correct order
    x = [
        constants[0],  # constant[0]
        k[0], k[1], k[2], k[3],  # key[0-3]
        constants[1],  # constant[1]
        n[0], n[1],  # nonce[0-1]
        counter & 0xFFFFFFFF, (counter >> 32) & 0xFFFFFFFF,  # counter[0-1]
        constants[2],  # constant[2]
        k[4], k[5], k[6], k[7],  # key[4-7]
        constants[3]   # constant[3]
    ]

    # Perform the Salsa20 core operations
    for i in range(20):
        if i % 2 == 0:
            x[0] += x[4]; x[12] ^= x[0]; x[12] = rotate(x[12], 16)
            x[1] += x[5]; x[13] ^= x[1]; x[13] = rotate(x[13], 12)
            x[2] += x[6]; x[14] ^= x[2]; x[14] = rotate(x[14], 8)
            x[3] += x[7]; x[15] ^= x[3]; x[15] = rotate(x[15], 7)
        else:
            x[0] += x[5]; x[13] ^= x[0]; x[13] = rotate(x[13], 16)
            x[1] += x[6]; x[14] ^= x[1]; x[14] = rotate(x[14], 12)
            x[2] += x[7]; x[15] ^= x[2]; x[15] = rotate(x[15], 8)
            x[3] += x[4]; x[12] ^= x[3]; x[12] = rotate(x[12], 7)

    # Create the p array as the output of the π function (rotation)
    p = [rotate(x[i], 7) for i in range(16)]  # Rotate x[i] by 7 bits

    # Combine the original x (H function) with the rotated p (π function)
    r = [((x[i] + p[i]) & 0xFFFFFFFF) for i in range(16)]  # Add H and π

    return struct.pack('<16L', *r)

def salsa20_encrypt(key, nonce, plaintext):
    # Initialize the ciphertext
    ciphertext = bytearray()
    
    # Process the plaintext in chunks of 64 bytes
    for i in range(0, len(plaintext), 64):
        # Generate the block of keystream
        block = salsa20_g(key, nonce, i // 64)
        
        # XOR with the plaintext
        for j in range(min(64, len(plaintext) - i)):
            ciphertext.append(plaintext[i + j] ^ block[j % 64])
    
    return bytes(ciphertext)

def generate_salsa20_key():
    return os.urandom(32)  # 256-bit key

def generate_nonce():
    return os.urandom(8)   # 64-bit nonce

# Example usage
if __name__ == "__main__":
    # Generate key and nonce
    key = generate_salsa20_key()
    nonce = generate_nonce()

    # Example plaintext
    plaintext = b"Hello, Salsa20! This is a test message."

    # Encrypt the plaintext
    ciphertext = salsa20_encrypt(key, nonce, plaintext)
    print("Ciphertext:", ciphertext.hex())

    # To decrypt, you would encrypt the ciphertext again with the same key and nonce
    decrypted_text = salsa20_encrypt(key, nonce, ciphertext)
    print("Decrypted Text:", decrypted_text.decode('utf-8'))
