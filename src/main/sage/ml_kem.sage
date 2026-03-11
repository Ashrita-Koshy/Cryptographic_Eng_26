n = 256
q = 3329
zeta = 17

def BitsToBytes(b):
    B = [0] * (len(b) // 8)
    for i in range(len(b)):
        B[i // 8] = B[i // 8] + (b[i] * 2^(i % 8))
    return B

def BytesToBits(B):
    b = [0] * (len(B) * 8)
    C = B[:]
    for i in range(len(B)):
        for j in range(8):
            b[(8*i + j)] = C[i] % 2
            C[i] = C[i] // 2
    return b

def Compress(d,x):
    return (round((2^d)*x/q)) % (2^d)

def Decompress(d,y):
    return round(q*y/(2^d))

def ByteEncode(d,F):
    b = [0] * (n * d)
    for i in range(n):
        a = F[i]
        for j in range(d):
            b[((i*d) + j)] = a % 2
            a = (a - b[((i*d) + j)])//2
    return BitsToBytes(b)

def ByteDecode(d,B):
    m = 2^d if d < 12 else q
    F = [0] * n
    b = BytesToBits(B)
    for i in range(n):
        for j in range(d):
            F[i] += (b[(i*d) + j] * 2^j) % m
    return F




