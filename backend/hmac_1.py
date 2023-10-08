# Função SHA-256 simples para substituir hashlib.sha256
def sha256(message):
    # Inicialização dos hashes
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    # Funções auxiliares
    def right_rotate(x, n):
        return (x >> n) | (x << (32 - n))

    def sig0(x):
        return right_rotate(x, 7) ^ right_rotate(x, 18) ^ (x >> 3)

    def sig1(x):
        return right_rotate(x, 17) ^ right_rotate(x, 19) ^ (x >> 10)

    def ch(x, y, z):
        return (x & y) ^ ((~x) & z)

    def maj(x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    # Preparação da mensagem (padding)
    message = pad_message(message)

    w = [0] * 64

    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        for j in range(16):
            w[j] = int.from_bytes(chunk[j*4:j*4+4], byteorder='big')
        for j in range(16, 64):
            s0 = sig0(w[j-15])
            s1 = sig1(w[j-2])
            w[j] = (w[j-16] + s0 + w[j-7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        for j in range(64):
            S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch_res = ch(e, f, g)
            temp1 = (h + S1 + ch_res + k[j] + w[j]) & 0xFFFFFFFF

            S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj_res = maj(a, b, c)
            temp2 = (S0 + maj_res) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF

    return (
        h0.to_bytes(4, 'big') +
        h1.to_bytes(4, 'big') +
        h2.to_bytes(4, 'big') +
        h3.to_bytes(4, 'big') +
        h4.to_bytes(4, 'big') +
        h5.to_bytes(4, 'big') +
        h6.to_bytes(4, 'big') +
        h7.to_bytes(4, 'big')
    )

# Função para calcular o HMAC usando o algoritmo SHA-256
def hmac_sha256(key, message):
    block_size = 64  # Tamanho do bloco em bytes
    sha256_block_size = 64  # Tamanho do bloco SHA-256 em bytes
    ipad = 0x36.to_bytes(1, 'big') * block_size
    opad = 0x5C.to_bytes(1, 'big') * block_size

    # Tratamento da chave
    if len(key) > block_size:
        key = sha256(key)
    if len(key) < block_size:
        key += b'\x00' * (block_size - len(key))

    inner_key = bytes(x ^ y for x, y in zip(key, ipad))
    inner_message = inner_key + message
    inner_hash = sha256(inner_message)

    outer_key = bytes(x ^ y for x, y in zip(key, opad))
    outer_message = outer_key + inner_hash
    hmac_result = sha256(outer_message)

    return hmac_result

# Função para preencher a mensagem com padding
def pad_message(message):
    message_length = len(message)
    bit_length = message_length * 8

    # Adiciona 1 no final dos dados
    message += b'\x80'

    # Preenche com zeros até que a mensagem seja congruente a 448 mod 512
    while len(message) % 64 != 56:
        message += b'\x00'

    # Adiciona o comprimento original da mensagem em bits como um inteiro de 64 bits no final
    message += bit_length.to_bytes(8, 'big')

    return message

# # Mensagem e chave secreta
# mensagem = "Mensagem secreta"
# senha = "ChaveSecreta123"

def getHash(password,message):
    # Calcula o HMAC da mensagem
    hmac_resultado = hmac_sha256(password.encode(), message.encode()) 
    return hmac_resultado.hex()

