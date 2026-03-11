import hashlib

n = 256
q = 3329
zeta = 17

def SHAKE128_Init():
    #ctx is a tuple containing the shake_128 object, and num of bytes already squeezed out
    return (hashlib.shake_128(),0)

def SHAKE128_Absorb(ctx,data):
    ctx[0].update(data)
    return ctx

def SHAKE128_Squeeze(ctx,len):
    total = len + ctx[1]
    C = ctx[0].digest(total)[-len:]
    return ((ctx[0],total),C)

def XOF_Init():
    return SHAKE128_Init()

def XOF_Absorb(ctx, data):
    return SHAKE128_Absorb(ctx, data)

def XOF_Squeeze(ctx, length):
    return SHAKE128_Squeeze(ctx, length)

def BitsToBytes(b):
    B = [0] * (len(b) // 8)
    for i in range(len(b)):
        B[i // 8] = B[i // 8] + (b[i] * 2^(i % 8))
    return B

def BytesToBits(B):
    b = [0] * (len(B) * 8)
    C = list(B[:])
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

def SampleNTT(B):
    ctx = XOF_Init()
    ctx = XOF_Absorb(ctx,B)
    j = 0
    a = [0] * n
    while j < n:
        ctx, C = XOF_Squeeze(ctx,3)
        d1 = C[0] + n*(C[1] % 16)
        d2 = C[1]//16 + 16*C[2]
        if d1 < q:
            a[j] = d1
            j += 1
        if (d2 < q) and (j < n):
            a[j] = d2
            j += 1
    return a

def SamplePolyCBD(eta,B):
    b = BytesToBits(B)
    f = [0] * n
    for i in range(n):
        x = sum([b[((2*i*eta) + j)] for j in range(eta)])
        y = sum([b[((2*i*eta) + eta + j)] for j in range(eta)])
        f[i] = (x-y) % q
    return f




