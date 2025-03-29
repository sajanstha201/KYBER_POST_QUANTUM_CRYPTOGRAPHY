# Kyber Post-Quantum KEM Library

This repository contains a reference implementation of the Kyber post-quantum Key Encapsulation Mechanism (KEM) from the [pq-crystals project](https://github.com/pq-crystals/kyber).

Kyber is one of the selected algorithms in the [NIST Post-Quantum Cryptography standardization process](https://csrc.nist.gov/projects/post-quantum-cryptography).

## Clone the Repository

```bash
git clone https://github.com/pq-crystals/kyber.git
cd kyber/ref

## Compile the Library

Kyber comes in three security levels, defined by the `KYBER_K` macro:

- `KYBER_K=2` → **Kyber512**
- `KYBER_K=3` → **Kyber768**
- `KYBER_K=4` → **Kyber1024**

---

### 🔧 macOS

Use `clang` to compile a shared dynamic library (`.dylib`):

```bash
clang -O3 -Wall -dynamiclib -o libkyber1024.dylib \
    kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c \
    randombytes.c fips202.c symmetric-shake.c -I. -lm -DKYBER_K=4

# Compiling Kyber with GCC on Ubuntu / Linux 🐧

Use `gcc` to compile the Kyber implementation into a shared object (`.so`) file. The security level is determined by the `-DKYBER_K` flag.

## Security Levels

- `-DKYBER_K=4` → **Kyber1024** (highest security)
- `-DKYBER_K=3` → **Kyber768**
- `-DKYBER_K=2` → **Kyber512** (lightest and fastest)

---

## Compilation Command

Use the following `gcc` command to compile Kyber:

```bash
gcc -O3 -Wall -fPIC -shared -o libkyber.so \
    kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c \
    randombytes.c fips202.c symmetric-shake.c -I. -lm -DKYBER_K=<level>
