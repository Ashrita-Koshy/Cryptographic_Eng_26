import hashlib

#Symbols as defined in FIPS 203 - Sect. 2.3
n = 256
q = 3329

#Parameter set for ML-KEM-1024 as defined in Sect. 8 Table 2.
k = 4
eta1 = 2
eta2 = 2
du = 11
dv = 5

#Precomputed Zeta powers as defined in FIPS 203 Appendix A
zetaPowers = (1, 1729, 2580, 3289, 2642, 630, 1897, 848, 
                1062, 1919, 193, 797, 2786, 3260, 569, 1746, 
                296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 
                1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 
                289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 
                650, 1977, 2513, 632, 2865, 33, 1320, 1915, 
                2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 
                2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 
                17, 2761, 583, 2649, 1637, 723, 2288, 1100, 
                1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 
                1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 
                939, 2308, 2437, 2388, 733, 2337, 268, 641, 
                1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 
                1063, 319, 2773, 757, 2099, 561, 2466, 2594, 
                2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 
                1722, 1212, 1874, 1029, 2110, 2935, 885, 2154)

#Precomputed Zeta odd powers as defined in FIPS 203 Appendix A
zetaOddPowers = (17,  -17, 2761, -2761,  583,  -583, 2649, -2649,
                1637, -1637,  723,  -723, 2288, -2288, 1100, -1100,
                1409, -1409, 2662, -2662, 3281, -3281,  233,  -233,
                756,  -756, 2156, -2156, 3015, -3015, 3050, -3050,
                1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789,
                1847, -1847,  952,  -952, 1461, -1461, 2687, -2687,
                939,  -939, 2308, -2308, 2437, -2437, 2388, -2388,
                733,  -733, 2337, -2337,  268,  -268,  641,  -641,
                1584, -1584, 2298, -2298, 2037, -2037, 3220, -3220,
                375,  -375, 2549, -2549, 2090, -2090, 1645, -1645,
                1063, -1063,  319,  -319, 2773, -2773,  757,  -757,
                2099, -2099,  561,  -561, 2466, -2466, 2594, -2594,
                2804, -2804, 1092, -1092,  403,  -403, 1026, -1026,
                1143, -1143, 2150, -2150, 2775, -2775,  886,  -886,
                1722, -1722, 1212, -1212, 1874, -1874, 1029, -1029,
                2110, -2110, 2935, -2935,  885,  -885, 2154, -2154)

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
    return [sum(b[8*i + j] * 2^j for j in range(8)) for i in range(len(b) // 8) ]

def BytesToBits(B):
    return [(B[i] >> j) & 1 for i in range(len(B)) for j in range(8)]

def Compress(d,x):
    return ZZ(round((2^d / q) * x)) % 2^d

def Decompress(d,y):
    return ZZ(round(q * y / 2^d))

def ByteEncode(d,F):
    return BitsToBytes([(F[i] >> j) & 1 for i in range(n) for j in range(d)])

def ByteDecode(d,B):
    m = 2^d if d < 12 else q
    b = BytesToBits(B)
    return [sum((b[i*d + j] * 2^j) % m for j in range(d)) for i in range(n)]

def SampleNTT(B):
    ctx = XOF_Init()
    ctx = XOF_Absorb(ctx, B)
    a = []
    while len(a) < n:
        ctx, C = XOF_Squeeze(ctx, 3)
        d1 = C[0] + n * (C[1] % 16)
        d2 = C[1]//16 + 16*C[2]
        if d1 < q:
            a.append(d1)
        if d2 < q and len(a) < n:
            a.append(d2)
    return a

def SamplePolyCBD(eta,B):
    b = BytesToBits(B)
    f = [0] * n
    for i in range(n):
        x = sum([b[((2*i*eta) + j)] for j in range(eta)])
        y = sum([b[((2*i*eta) + eta + j)] for j in range(eta)])
        f[i] = (x-y) % q
    return f

def NTT(f):
    f_hat = f[:]
    i = 1
    len = 128
    while len >= 2:
        for start in range(0,256,2*len):
            zeta = zetaPowers[i]
            i += 1
            for j in range(start,(start + len)):
                t = (zeta * f_hat[(j+len)]) % q
                f_hat[(j + len)] = (f_hat[j] - t) % q
                f_hat[j] = (f_hat[j] + t) % q
        len = len >> 1
    return f_hat

def NTTInverse(f_hat):
    f = f_hat[:]
    i = 127
    len = 2
    while len <= 128:
        for start in range(0,256,2*len):
            zeta = zetaPowers[i]
            i -= 1
            for j in range(start,(start + len)):
                t = f[j]
                f[j] = (t + f[(j + len)]) % q
                f[(j + len)] = (zeta*(f[(j + len)] - t)) % q
        len = len << 1
    for i in range(n):
        f[i] = (f[i] * 3303) % q
    return f

def BaseCaseMultiply(a0,a1,b0,b1,gamma):
    c0 = ((a0*b0) + (a1*b1*gamma)) % q
    c1 = ((a0*b1) + (a1*b0)) % q
    return (c0,c1)

def MultiplyNTTs(f,g):
    h = [0] * 256
    for i in range(128):
        h[2*i],h[2*i + 1] = BaseCaseMultiply(f[2*i],f[2*i + 1],g[2*i],g[2*i + 1],zetaOddPowers[i])
    return h


# Helper functions
def H(x):
    return hashlib.sha3_256(x).digest()

def G(x):
    g = hashlib.sha3_512(x).digest()
    K = g[:32]
    r = g[32:]
    return (K,r)

def J(x):
    return hashlib.shake_256(x).digest(32)

# Algorithm 16
def ML_KEM_KeyGen_internal(d,z):
    (ekPKE,dkPKE) = K_PKE_KeyGen(d)         # Algorithm 13 used here
    ek = ekPKE
    dk = dkPKE + ek + H(ek) + z
    return (ek,dk)

# Algorithm 17
def ML_KEM_Encaps_internal(ek,m):
    (K,r) = G(m + H(ek))
    c = K_PKE_Encrypt(ek,m,r)               # Algorithm 14 used here
    return (K,c)

# Algorithm 18
def ML_KEM_Decaps_internal(dk,c):
    dkPKE = dk[0 : 384*k]
    ekPKE = dk[384*k : 768*k + 32]
    h = dk[768*k + 32 : 768*k + 64]
    z = dk[768*k + 64 : 768*k + 96]
    m_prime = K_PKE_Decrypt(dkPKE, c)          # Algorithm 15 used here
    K_prime, r_prime = G(m_prime + h)
    K_bar = J(z + c)
    c_prime = K_PKE_Encrypt(ekPKE, m_prime, r_prime)        # Algorithm 14 used here
    if c != c_prime:
        K_prime = K_bar
    return K_prime