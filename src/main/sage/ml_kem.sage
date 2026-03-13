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

def Round(x,y):
    offset = y//2 if ((x < 0) == (y < 0)) else (-1*y)//2
    return (x + offset)//y

def Compress(d,x):
    return ZZ(Round(((2^d)*ZZ(x)),q)) % 2^d

def Decompress(d,y):
    return ZZ(Round((q * ZZ(y)),2^d))

def ByteEncode(d,F):
    return BitsToBytes([(ZZ(F[i]) >> j) & 1 for i in range(n) for j in range(d)])

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
    length = 128
    while length >= 2:
        for start in range(0,256,2*length):
            zeta = zetaPowers[i]
            i += 1
            for j in range(start,(start + length)):
                t = (zeta * f_hat[(j+length)]) % q
                f_hat[(j + length)] = (f_hat[j] - t) % q
                f_hat[j] = (f_hat[j] + t) % q
        length = length >> 1
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

def PRF(eta,s,b):
    return hashlib.shake_256(s + bytes([b])).digest(64*eta)

def MultiplyNTTMatrix(A,u_hat,isTranspose = False):
    w_hat = [vector(Integers(q),[0] * n)] * k
    for i in range(k):
        for j in range(k):
            product = MultiplyNTTs(A[i][j],u_hat[j]) if not isTranspose else MultiplyNTTs(A[j][i],u_hat[j])
            w_hat[i] = vector(Integers(q),[(w_hat[i][c] + product[c]) for c in range(n)])
    return w_hat

def MultiplyNTTVector(u_hat,v_hat):
    z_hat = vector(Integers(q),[0] * n)
    for j in range(k):
        product = MultiplyNTTs(u_hat[j],v_hat[j])
        z_hat = vector(Integers(q),[(z_hat[c] + product[c]) for c in range(n)])
    return z_hat

def K_PKE_KeyGen(d):
    rho, sigma = G(d + bytes([k]))
    N = 0
    A = [[None] * k for _ in range(k)]
    for i in range(k):
        for j in range(k):
            A[i][j] = vector(Integers(q),SampleNTT(rho + bytes([j,i])))
    s = [None] * k
    for i in range(k):
        s[i] = vector(Integers(q),SamplePolyCBD(eta1,PRF(eta1,sigma,N)))
        N += 1
    e = [None] * k
    for i in range(k):
        e[i] = vector(Integers(q),SamplePolyCBD(eta1,PRF(eta1,sigma,N)))
        N += 1
    s_hat = [vector(Integers(q),NTT(s[i])) for i in range(k)]
    e_hat = [vector(Integers(q),NTT(e[i])) for i in range(k)]
    t_hat = MultiplyNTTMatrix(A,s_hat)
    t_hat = [(t_hat[i] + e_hat[i]) for i in range(k)]
    ek_PKE = b''
    for poly in t_hat:
        ek_PKE += bytes(ByteEncode(12,poly))
    ek_PKE += rho
    dk_PKE = b''
    for poly in s_hat:
        dk_PKE += bytes(ByteEncode(12,poly))
    return ek_PKE, dk_PKE

def K_PKE_Encrypt(ek_PKE,m,r):
    N = 0
    t_hat = [vector(Integers(q),ByteDecode(12,ek_PKE[(384*i):(384*(i+1))])) for i in range(k)]
    rho = ek_PKE[-(32):]
    A = [[None] * k for _ in range(k)]
    for i in range(k):
        for j in range(k):
            A[i][j] = vector(Integers(q),SampleNTT(rho + bytes([j,i])))
    y = [None] * k
    for i in range(k):
        y[i] = vector(Integers(q),SamplePolyCBD(eta1,PRF(eta1,r,N)))
        N += 1
    e1 = [None] * k
    for i in range(k):
        e1[i] = vector(Integers(q),SamplePolyCBD(eta2,PRF(eta2,r,N)))
        N += 1
    e2 = vector(Integers(q),SamplePolyCBD(eta2,PRF(eta2,r,N)))
    y_hat = [vector(Integers(q),NTT(y[i])) for i in range(k)]
    u_hat = MultiplyNTTMatrix(A,y_hat,True)
    u = [vector(Integers(q),NTTInverse(poly)) for poly in u_hat]
    u = [(u[i] + e1[i]) for i in range(k)]
    mu = vector(Integers(q),[Decompress(1,val) for val in ByteDecode(1,m)])
    upsilon = vector(Integers(q),NTTInverse(MultiplyNTTVector(t_hat,y_hat))) + e2 + mu
    c1 = b''
    for poly in u:
        compression = [Compress(du,val) for val in poly]
        c1 += bytes(ByteEncode(du,compression))
    c2 = b''
    c2 += bytes(ByteEncode(dv,[Compress(dv,val) for val in upsilon]))
    return (c1 + c2)

def K_PKE_Decrypt(dk_PKE,c):
    c1 = c[:(32*du*k)]
    c2 = c[(32*du*k):]
    u_prime = [None] * k
    for i in range(k):
        f = ByteDecode(du,c1[(32*du*i):(32*du*(i+1))])
        u_prime[i] = vector(Integers(q),[Decompress(du,val) for val in f])
    upsilon_prime = vector(Integers(q),[Decompress(dv,val) for val in ByteDecode(dv,c2)])
    s_hat = [None] * k
    for i in range(k):
        s_hat[i] = vector(Integers(q),ByteDecode(12,dk_PKE[(32*12*i):(32*12*(i+1))]))
    u_prime_hat = [vector(Integers(q),NTT(poly)) for poly in u_prime]
    w = upsilon_prime - vector(Integers(q),NTTInverse(MultiplyNTTVector(s_hat,u_prime_hat)))
    compressed = [Compress(1,val) for val in w]
    return bytes(ByteEncode(1,compressed))

# Algorithm 16
def _ML_KEM_KeyGen_internal(d,z):
    ekPKE, dkPKE = K_PKE_KeyGen(d)
    ek = ekPKE
    dk = dkPKE + ek + H(ek) + z
    return (ek,dk)

# Algorithm 17
def _ML_KEM_Encaps_internal(ek,m):
    (K,r) = G(m + H(ek))
    c = K_PKE_Encrypt(ek,m,r)
    return (K,c)

# Algorithm 18
def _ML_KEM_Decaps_internal(dk,c):
    dkPKE = dk[0 : 384*k]
    ekPKE = dk[384*k : 768*k + 32]
    h = dk[768*k + 32 : 768*k + 64]
    z = dk[768*k + 64 : 768*k + 96]
    m_prime = K_PKE_Decrypt(dkPKE, c)
    K_prime, r_prime = G(m_prime + h)
    K_bar = J(z + c)
    c_prime = K_PKE_Encrypt(ekPKE, m_prime, r_prime)
    if c != c_prime:
        K_prime = K_bar
    return K_prime

def ML_KEM_KeyGen():
    d = os.urandom(32)
    z = os.urandom(32)
    if d == None or z == None:
        return None
    return _ML_KEM_KeyGen_internal(d,z)

def ML_KEM_Encaps(ek):
    if type(ek) is not bytes:
        raise TypeError(f"Encryption Key must be bytes array, got {type(ek)}")
    if len(ek) != (384*k + 32):
        raise ValueError(f"Encryption key must contain {(384*k + 32)} bytes")
    test = b''
    for i in range(k):
        test += bytes(ByteEncode(12,ByteDecode(12,ek[384*i:(384*(i+1))])))
    if test != ek[0:384*k]:
        raise ValueError(f'Encryption key must contain integers modulo {q}')
    m = os.urandom(32)
    if m == None:
        return None
    return _ML_KEM_Encaps_internal(ek,m)

def ML_KEM_Decaps(dk,c):
    if type(c) is not bytes:
        raise TypeError(f"Ciphertext must be bytes array, got {type(c)}")
    if len(c) != (32*(du*k + dv)):
        raise ValueError(f"Ciphertext must contain {(32*(du*k + dv))} bytes")
    if type(dk) is not bytes:
        raise TypeError(f"Decryption Key must be bytes array, got {type(dk)}")
    if len(dk) != (768*k + 96):
        raise ValueError(f"Decryption key must contain {(768*k + 96)} bytes")
    test = H(dk[384*k:(768*k+32)])
    if test != dk[(768*k + 32):(768*k + 64)]:
        raise ValueError("Decryption Key failed Hash check")
    return _ML_KEM_Decaps_internal(dk,c)


