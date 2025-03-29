import ctypes

# Load the shared Kyber1024 library
lib = ctypes.cdll.LoadLibrary('./kyber/ref/libkyber1024.dylib')  # You can rename this to libkyber1024.dylib for clarity

# Kyber1024 parameter sizes (from params.h)
PK_LEN = 1568   # CRYPTO_PUBLICKEYBYTES for Kyber1024
SK_LEN = 3168   # CRYPTO_SECRETKEYBYTES
CT_LEN = 1568   # CRYPTO_CIPHERTEXTBYTES
SS_LEN = 32     # CRYPTO_BYTES (shared secret length)

# Bind the correct function names from nm
lib.pqcrystals_kyber1024_ref_keypair.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),  # pk
    ctypes.POINTER(ctypes.c_ubyte)   # sk
]
lib.pqcrystals_kyber1024_ref_enc.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),  # ct
    ctypes.POINTER(ctypes.c_ubyte),  # ss
    ctypes.POINTER(ctypes.c_ubyte)   # pk
]
lib.pqcrystals_kyber1024_ref_dec.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),  # ss
    ctypes.POINTER(ctypes.c_ubyte),  # ct
    ctypes.POINTER(ctypes.c_ubyte)   # sk
]

# Python wrapper for Kyber1024 keypair generation
def kyber1024_keygen():
    pk = (ctypes.c_ubyte * PK_LEN)()
    sk = (ctypes.c_ubyte * SK_LEN)()
    lib.pqcrystals_kyber1024_ref_keypair(pk, sk)
    return bytes(pk), bytes(sk)

# Python wrapper for Kyber1024 encapsulation
def kyber1024_encapsulate(pk: bytes):
    assert len(pk) == PK_LEN
    ct = (ctypes.c_ubyte * CT_LEN)()
    ss = (ctypes.c_ubyte * SS_LEN)()
    pk_buf = (ctypes.c_ubyte * PK_LEN).from_buffer_copy(pk)
    lib.pqcrystals_kyber1024_ref_enc(ct, ss, pk_buf)
    return bytes(ct), bytes(ss)

# Python wrapper for Kyber1024 decapsulation
def kyber1024_decapsulate(ct: bytes, sk: bytes):
    assert len(ct) == CT_LEN
    assert len(sk) == SK_LEN
    ss = (ctypes.c_ubyte * SS_LEN)()
    ct_buf = (ctypes.c_ubyte * CT_LEN).from_buffer_copy(ct)
    sk_buf = (ctypes.c_ubyte * SK_LEN).from_buffer_copy(sk)
    lib.pqcrystals_kyber1024_ref_dec(ss, ct_buf, sk_buf)
    return bytes(ss)

# 🔐 Test script
if __name__ == "__main__":
    print("🔐 Generating Kyber1024 Keypair...")
    pk, sk = kyber1024_keygen()
    
    print("📦 Encapsulating Shared Secret...")
    ct, ss_enc = kyber1024_encapsulate(pk)

    print("🔓 Decapsulating Shared Secret...")
    ss_dec = kyber1024_decapsulate(ct, sk)

    print("\nShared Secret (Encapsulated):", ss_enc.hex())
    print("Shared Secret (Decapsulated):", ss_dec.hex())
    print("✅ Match:", ss_enc == ss_dec)
