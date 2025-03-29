import ctypes

# Load the shared Kyber768 library
lib = ctypes.cdll.LoadLibrary('./kyber/ref/libkyber768.dylib')  # You can rename this to libkyber768.dylib for clarity

# Kyber768 parameter sizes (from params.h)
PK_LEN = 1184   # CRYPTO_PUBLICKEYBYTES for Kyber768
SK_LEN = 2400   # CRYPTO_SECRETKEYBYTES
CT_LEN = 1088   # CRYPTO_CIPHERTEXTBYTES
SS_LEN = 32     # CRYPTO_BYTES (shared secret length)

# Bind the correct function names from nm
lib.pqcrystals_kyber768_ref_keypair.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),  # pk
    ctypes.POINTER(ctypes.c_ubyte)   # sk
]
lib.pqcrystals_kyber768_ref_enc.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),  # ct
    ctypes.POINTER(ctypes.c_ubyte),  # ss
    ctypes.POINTER(ctypes.c_ubyte)   # pk
]
lib.pqcrystals_kyber768_ref_dec.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),  # ss
    ctypes.POINTER(ctypes.c_ubyte),  # ct
    ctypes.POINTER(ctypes.c_ubyte)   # sk
]

# Python wrapper for Kyber768 keypair generation
def kyber768_keygen():
    pk = (ctypes.c_ubyte * PK_LEN)()
    sk = (ctypes.c_ubyte * SK_LEN)()
    lib.pqcrystals_kyber768_ref_keypair(pk, sk)
    return bytes(pk), bytes(sk)

# Python wrapper for Kyber768 encapsulation
def kyber768_encapsulate(pk: bytes):
    assert len(pk) == PK_LEN
    ct = (ctypes.c_ubyte * CT_LEN)()
    ss = (ctypes.c_ubyte * SS_LEN)()
    pk_buf = (ctypes.c_ubyte * PK_LEN).from_buffer_copy(pk)
    lib.pqcrystals_kyber768_ref_enc(ct, ss, pk_buf)
    return bytes(ct), bytes(ss)

# Python wrapper for Kyber768 decapsulation
def kyber768_decapsulate(ct: bytes, sk: bytes):
    assert len(ct) == CT_LEN
    assert len(sk) == SK_LEN
    ss = (ctypes.c_ubyte * SS_LEN)()
    ct_buf = (ctypes.c_ubyte * CT_LEN).from_buffer_copy(ct)
    sk_buf = (ctypes.c_ubyte * SK_LEN).from_buffer_copy(sk)
    lib.pqcrystals_kyber768_ref_dec(ss, ct_buf, sk_buf)
    return bytes(ss)

# 🔐 Test script
if __name__ == "__main__":
    print("🔐 Generating Kyber768 Keypair...")
    pk, sk = kyber768_keygen()

    print("📦 Encapsulating Shared Secret...")
    ct, ss_enc = kyber768_encapsulate(pk)

    print("🔓 Decapsulating Shared Secret...")
    ss_dec = kyber768_decapsulate(ct, sk)

    print("\nShared Secret (Encapsulated):", ss_enc.hex())
    print("Shared Secret (Decapsulated):", ss_dec.hex())
    print("✅ Match:", ss_enc == ss_dec)
