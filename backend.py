# TABLES
IP_TABLE = [
    58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7
]

PC1_TABLE = [
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
]

SHIFT_TABLE = [
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

PC2_TABLE = [
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
]

E_TABLE = [
    32,  1,  2,  3,  4,  5,
    4,  5,  6,  7,  8,  9,
    8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
]

P_TABLE = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

S_TABLE = {
    "1": [
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
            0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
            4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
            15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
        ],
    "2": [
            15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
            3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
            0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
            13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
        ],
    "3": [
            10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
            13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
            13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
            1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
        ],
    "4": [
            7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
            13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
            10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
            3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
        ],
    "5": [
            2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
            14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
            4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
            11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
        ],
    "6": [
            12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
            10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
            9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
            4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
        ],
    "7": [
            4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
            13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
            1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
            6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
        ],
    "8": [
            13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
            1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
            7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
            2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
        ]
}

IP_1_TABLE = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]


# METHODS
# fundamental methods
def str2bin(string: str, enc_n_bits: int=8):
    """
    Convert string to binary string
    """
    bins = []
    for char in string:
        _bin = bin(ord(char))[2:]
        bins.append("0"*(enc_n_bits-len(_bin))+_bin)
    return ''.join(bins)

def bin2str(binary: str, enc_n_bits: int=8):
    """
    Convert binary string to string
    """
    assert len(binary) // enc_n_bits, "binary string incomplete !" 
    return ''.join([chr(i) for i in [int(binary[j*enc_n_bits:(j+1)*enc_n_bits], 2) for j in range(len(binary)//enc_n_bits)]])

def binstr2bytes(s):
    """
    Convert binary string to bytes
    """
    assert len(s) % 8 == 0, "input lenght should be multiple of 8"
    return bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8))

def bytes2binstr(b, n=None):
    """
    Convert bytes to binary string
    """
    s = ''.join(f'{x:08b}' for x in b)
    return s if n is None else s[:n + n // 8 + (0 if n % 8 else -1)]

def int2bin(a, n):
    """
    Convert int to binary string
    """
    assert 0<=n and a < 2**n
    res = [0] * n

    for x in range(n):
        res[n-x-1] = a % 2
        a = a // 2
    return ''.join([str(i) for i in res])
    
def fill_multiple_of_64(binary: str):
    """
    Fill binary string with zeros 
    (length of output is multiple of 64)
    """
    remaining = len(binary) % 64
    if remaining != 0:
        remaining = remaining if len(binary)>64 else 64-remaining
    return binary + "0" * remaining

def left_shift(binary, n):
    """
    Left shift operation
    """
    return binary[n:] + binary[:n]

def xor(b1, b2):
    """
    XOR operation
    """
    len1, len2 = len(b1), len(b2)
    assert len1 == len2, "length of binary 1 and binary 2 is not equal"
    return "".join([str(1 - int(c1 == c2)) for c1, c2 in zip(b1, b2)])


# DES key methods
def reshape_key_to_64(binary):
    """
    Reshape key to 64 bits
    (remove/padding zeros)
    """
    length = len(binary)
    if length > 64:
        return binary[:64]
    else:
        return binary + "0"*(64-length)

def pc1_replace(binary):
    """
    Replacement using PC-1 table
    """
    assert len(binary) == 64, "extrated key is not equal to 64 !"
    return "".join([binary[PC1_TABLE[i]-1] for i in range(56)])

def pc2_replace(binary): 
    """
    Replacement using PC-2 table
    """
    assert len(binary) == 56, "extrated key is not equal to 56 !"
    return "".join([binary[PC2_TABLE[i]-1] for i in range(48)])

def key_iterate_16s(binary):
    """
    Generate sub-keys
    """
    c, d = binary[:28], binary[28:]
    keys = []
    for i in range(16):
        c = left_shift(c, SHIFT_TABLE[i])
        d = left_shift(d, SHIFT_TABLE[i])
        keys.append(pc2_replace(c+d))
    return keys
    

# DES message methods
def ip_replace(binary):
    """
    Replacement using IP table
    """
    assert len(binary) == 64, "message binary is not equal to 64 !"
    return "".join([binary[IP_TABLE[i]-1] for i in range(64)])

def e_box_replace(binary):
    """
    Replacement using E table
    """
    assert len(binary) == 32, "e box selection input is not equal to 32 !"
    return "".join([binary[E_TABLE[i]-1] for i in range(48)])

def s_box_replace(binary):
    """
    Replacement using S table
    """
    assert len(binary) == 48, "s box selection input is not equal to 48 !"
    replaced = ""
    for i in range(8):
        sub = binary[i*6:(i+1)*6]
        row_idx = int(sub[0]+sub[-1], 2)
        col_idx = int(sub[1:5], 2)
        num = S_TABLE[str(i+1)][row_idx*16+col_idx]
        replaced += int2bin(num, 4)
    return replaced

def p_box_replace(binary):
    """
    Replacement using P table
    """
    assert len(binary) == 32, "p box selection input is not equal to 32 !"
    return "".join([binary[P_TABLE[i]-1] for i in range(32)])

# DES F function
def f_func(r, k):
    """
    F function
    """
    r = e_box_replace(r)
    xor_out = xor(r, k)
    sbox_out = s_box_replace(xor_out)
    return p_box_replace(sbox_out)

def encode_one_iter(r, l, k):
    """
    One iteration of the 16 iters of encoding
    """
    return r, xor(l, f_func(r, k))

def encode_iterate_16s(r0, l0, keys):
    """
    Repeat "encode_one_iter" 16 times
    """
    r, l = r0, l0
    for i in range(16):
        l, r = encode_one_iter(r, l, keys[i])
    return r+l
    
def ip_1_replace(binary):
    """
    Replacement using IP-1 table
    """
    assert len(binary) == 64, "ip-1 box selection input is not equal to 64 !"
    return "".join([binary[IP_1_TABLE[i]-1] for i in range(64)])

# Build them together
def des_64bit(msg_bin: str, key_bin: str, inverse_subkeys: bool=False):
    """
    DES on 16-bits input
    """
    msg_bin = fill_multiple_of_64(msg_bin)
    ip_out = ip_replace(msg_bin)
    pc1_out = pc1_replace(key_bin)
    sub_keys = key_iterate_16s(pc1_out)
    if inverse_subkeys:
        # for decoding 
        sub_keys = sub_keys[::-1]
    l0, r0 = ip_out[:32], ip_out[32:]
    enc_16s_out = encode_iterate_16s(r0, l0, sub_keys)
    return ip_1_replace(enc_16s_out)

def des_wrapper(msg: str, key: str, inverse_subkeys: bool=False, use_bi_msg: bool=False, callback=None):
    """
    Wrapper of DES

    Message will be encoded into 16bits/char
    Key will be encoded into 8bits/char
    """
    binary_key = str2bin(key, enc_n_bits=8)
    if use_bi_msg:
        binary_msg = msg
    else:
        binary_msg = str2bin(msg, enc_n_bits=16)
    length = len(binary_msg)
    # assert len(binary_key)==64, "length of key should be equal to 64"
    binary_key = reshape_key_to_64(binary_key)
    if length <= 64:
        if callback is not None:
            callback(1)
        return des_64bit(binary_msg, binary_key, inverse_subkeys)
    else:
        res = ""
        n = length // 64
        remaining = length - n * 64
        n_ = n if remaining == 0 else n+1
        for i in range(n):
            res += des_64bit(binary_msg[i*64:(i+1)*64], binary_key, inverse_subkeys)
            if callback is not None:
                callback((i+1) / n_)
        if remaining > 0:
            res += des_64bit(binary_msg[n*64:], binary_key, inverse_subkeys)
            if callback is not None:
                callback(1)
        return res

def des_encode(msg: str, key: str, callback=None):
    """
    DES encryption
    """
    return des_wrapper(msg, key, callback=callback)
        
def des_decode(enc_msg: str, key: str, callback=None):
    """
    DES decryption
    """
    return des_wrapper(enc_msg, key, inverse_subkeys=True, use_bi_msg=True, callback=callback)


if __name__ == "__main__":
    message = "helloabc"
    key = "aaaaaaaa"

    print("Message: {}".format(message))
    print("Key: {}".format(key))

    enc_msg = des_encode(message, key)
    print("Encoded Message: {}".format(enc_msg))

    dec_msg = bin2str(des_decode(enc_msg, key)).strip()
    print("Decoded Message: {}".format(dec_msg))
    