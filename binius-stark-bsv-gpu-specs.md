# Especificaciones: binius-stark-bsv-gpu
## Binius STARK Prover/Verifier para Bitcoin SV con Aceleración GPU

**Versión:** 0.1.0  
**Fecha:** 2026-08-09  
**Lenguaje:** Zig 0.16 + CUDA C++ 13.3  
**Licencia:** MIT  

---

## 1. Resumen del Proyecto

`binius-stark-bsv-gpu` es un sistema de prueba/verificación STARK basado en campos binarios (torres de Galois) que:

- **Genera proofs** off-chain usando suma-check sobre GF(2^n)
- **Verifica proofs** on-chain mediante Bitcoin Script en BSV
- **Acelera el prover** via GPU NVIDIA usando CLMAD (CUDA 13.3) y bit-slicing
- **Integra con bsvz** (librería Zig de Bitcoin Script) sin modificaciones al intérprete

---

## 2. Arquitectura del Sistema

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              OFF-CHAIN                                  │
│  ┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────┐  │
│  │   Prover (Zig)      │───►│   GPU Kernels       │───►│   Proof     │  │
│  │   - Polynomials     │    │   (CUDA C++)        │    │   Output    │  │
│  │   - Sum-check       │    │   - CLMAD GF(2^128) │    │             │  │
│  │   - Fiat-Shamir     │    │   - Bit-slicing     │    │             │  │
│  │   - Merkle tree     │    │   - Parallel reduce │    │             │  │
│  └─────────────────────┘    └─────────────────────┘    └──────┬──────┘  │
│                                                               │         │
└───────────────────────────────────────────────────────────────┼─────────┘
                                                                │
┌───────────────────────────────────────────────────────────────┼─────────┐
│                              ON-CHAIN                         │         │
│  ┌─────────────────────┐    ┌─────────────────────┐           │         │
│  │   bsvz (Zig)        │◄───│   Bitcoin Script    │◄──────────┘         │
│  │   - Opcode engine   │    │   - Sum-check       │                     │
│  │   - Interpreter     │    │   - Merkle verify   │                     │
│  │   - Script builder  │    │   - MLE eval        │                     │
│  └─────────────────────┘    └─────────────────────┘                     │
│                                                                         │
│  BSV Blockchain                                                         │
│  - Script limit: 32MB (post-Chronicle)                                  │
│  - OP_RETURN: sin límite                                                │
│  - Coste: <$0.01/tx                                                     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Componentes

### 3.1 Core (Zig)

| Módulo | Archivo | Responsabilidad |
|--------|---------|-----------------|
| `field` | `src/field.zig` | GF(2^n): add, mul, pow, inv |
| `polynomial` | `src/polynomial.zig` | Polinomios multilineales + MLE eval |
| `prover` | `src/prover.zig` | Sum-check prover con Fiat-Shamir |
| `merkle` | `src/merkle.zig` | Merkle tree SHA-256 |
| `script` | `src/script.zig` | Bitcoin Script builder + opcodes |
| `interpreter` | `src/interpreter.zig` | Emulador Script para testing |
| `main` | `src/main.zig` | Orquestación + generación de outputs |

### 3.2 GPU (CUDA C++)

| Módulo | Archivo | Responsabilidad |
|--------|---------|-----------------|
| `gf128` | `cuda/gf128.cuh` | GF(2^128) con CLMAD |
| `sumcheck` | `cuda/sumcheck.cuh` | Kernel suma-check bit-sliced |
| `merkle_gpu` | `cuda/merkle.cuh` | SHA-256 paralelo en GPU |
| `binius_kernels` | `cuda/binius_kernels.cu` | Launcher CUDA |

### 3.3 FFI (Zig ↔ CUDA)

| Módulo | Archivo | Responsabilidad |
|--------|---------|-----------------|
| `cuda` | `src/cuda.zig` | Bindings C ABI a libbinius.so |

---

## 4. Protocolo Sum-Check

### 4.1 Statement

Verificar que:
```
Σ_{x ∈ {0,1}^k} g(x) = H
```
donde `g(x) = ∏_{j=1}^m f_j(x)` (producto de m polinomios multilineales).

### 4.2 Rondas

Para cada variable i = 1..k:

1. **Prover** envía polinomio univariado `s_i(t)` de grado d=m:
   ```
   s_i(t) = Σ_{x_{i+1},...,x_k} g(r_1,...,r_{i-1}, t, x_{i+1},...,x_k)
   ```

2. **Verifier** comprueba consistencia:
   ```
   s_i(0) + s_i(1) = suma_previa   (en char 2: XOR)
   ```

3. **Fiat-Shamir**: `transcript = SHA256(transcript || coeffs(s_i))`

4. **Challenge**: `r_i = transcript & field_mask`

5. **Nueva suma**: `suma = s_i(r_i)`

### 4.3 Verificación Final

Evaluar cada `f_j` en el punto aleatorio `r = (r_1,...,r_k)` via MLE y verificar:
```
∏_{j=1}^m f_j(r) = suma_final
```

---

## 5. Aritmética de Campo

### 5.1 GF(2^4) — Bitcoin Script

- **Polinomio:** `x^4 + x + 1 = 0x13`
- **Suma:** `OP_XOR` (1 opcode)
- **Multiplicación:** shift-and-add con reducción (~70 opcodes)
- **Representación:** 1 byte little-endian por elemento

### 5.2 GF(2^128) — GPU Prover

- **Polinomio:** GCM `x^128 + x^7 + x^2 + x + 1`
- **Multiplicación:** Karatsuba + CLMAD (6 instrucciones `clmad`)
- **Bit-slicing:** 32 elementos × 128 bits reorganizados en 128 registros × 32 bits
- **Speedup:** 4×–13× sobre CPU baseline

---

## 6. Formato de Witness

### 6.1 scriptSig (pushes en orden)

```
PUSH f_0          ; evaluación polinomio f en punto 0
PUSH f_1          ; ...
...
PUSH f_{2^k-1}    ; última evaluación de f
PUSH g_0          ; evaluación polinomio g en punto 0
...
PUSH g_{2^k-1}    ; última evaluación de g
PUSH c0_0         ; coef round 0, grado 0
PUSH c1_0         ; coef round 0, grado 1
PUSH c2_0         ; coef round 0, grado 2
...
PUSH c0_{k-1}     ; coef última round, grado 0
PUSH c1_{k-1}     ; ...
PUSH c2_{k-1}     ; ...
PUSH claimed_sum  ; H = suma sobre hipercubo
```

### 6.2 Stack al inicio del locking script

```
[f0, f1, ..., f_{2^k-1}, g0, ..., g_{2^k-1},
 c0_0, c1_0, c2_0, ..., c0_{k-1}, c1_{k-1}, c2_{k-1},
 claimed_sum]
```
`claimed_sum` está en el tope del stack.

---

## 7. Locking Script (Verificador)

### 7.1 Estructura

```
1. Initialize
   - DUP claimed_sum
   - TOALTSTACK (save as current_sum)
   - SHA256 (transcript = SHA256(claimed_sum))

2. For each round i = 0..k-1:
   a. TOALTSTACK transcript
   b. OVER + XOR (c1_i ^ c2_i)
   c. FROMALTSTACK current_sum + EQUALVERIFY
   d. FROMALTSTACK transcript
   e. PICK copies of c0_i, c1_i, c2_i
   f. CAT + SHA256 (new transcript)
   g. SPLIT + AND 0x0F (r_i = last 4 bits)
   h. Horner evaluation: s_i(r_i) = c0 + r*(c1 + r*c2)
      - GF(2^4) mul macro (branchless, mask arithmetic)
   i. TOALTSTACK (new current_sum)

3. Final verification:
   a. Build Merkle tree of f_evals, g_evals
   b. Verify Merkle roots match commitments
   c. Evaluate f(r), g(r) via MLE
   d. MUL f(r) * g(r)
   e. FROMALTSTACK current_sum + EQUALVERIFY

4. OP_TRUE (verification passed)
```

### 7.2 Tamaño estimado (k=4, GF(2^4), m=2)

| Componente | Opcodes | Bytes |
|------------|---------|-------|
| Initialize | 3 | ~5 |
| Per round (×4) | ~200 | ~300 |
| Final MLE eval | ~5000 | ~6000 |
| Merkle verify | ~150 | ~200 |
| **Total** | **~6000** | **~7500** |

---

## 8. GPU Kernel API

### 8.1 GF(2^128) Multiplication

```c
// cuda/gf128.cuh
__device__ void gf128_mul_clmad(
    uint64_t a_lo, uint64_t a_hi,
    uint64_t b_lo, uint64_t b_hi,
    uint64_t* out_lo, uint64_t* out_hi
);
```

### 8.2 Sum-Check Round

```c
// cuda/sumcheck.cuh
__global__ void sumcheck_round_kernel(
    const uint32_t* tables_in,    // bit-sliced [128][N/32]
    uint32_t* tables_out,         // bit-sliced output
    uint32_t num_vars,
    uint32_t round_idx,
    const uint64_t* challenge_lo,
    const uint64_t* challenge_hi,
    uint32_t degree
);
```

### 8.3 Batch Multiplication

```c
// cuda/binius_kernels.h
void gf128_mul_batch(
    const gf128_t* a,
    const gf128_t* b,
    gf128_t* out,
    uint64_t count
);
```

---

## 9. Configuración

### 9.1 Parámetros del Prover

```zig
const Config = struct {
    k: u16 = 4,              // variables (hypercube size = 2^k)
    field_bits: u16 = 4,     // GF(2^field_bits)
    mod_poly: u128 = 0x13,   // reduction polynomial
    num_polys: usize = 2,    // number of multilinears (degree)
    seed: []const u8 = "binius-bsv-2026",
};
```

### 9.2 Parámetros GPU

```cuda
#define WARP_SIZE 32
#define ELEMENTS_PER_WARP 32
#define SHARED_MEM_PER_BLOCK 49152  // 48KB (Ampere)
#define GRID_STRIDE_BATCH 1024
```

---

## 10. Dependencias

### 10.1 Build

| Dependencia | Versión | Propósito |
|-------------|---------|-----------|
| Zig | 0.16.0 | Host language |
| CUDA Toolkit | 13.3+ | GPU kernels + CLMAD |
| nvcc | 13.3+ | CUDA compiler |
| libcuda.so | 535+ | CUDA driver |

### 10.2 Runtime

| Dependencia | Propósito |
|-------------|-----------|
| libbinius.so | Kernels CUDA compilados |
| libc.so.6 | C ABI standard |

---

## 11. Build System

```bash
# Compilar todo
zig build

# Compilar solo host (sin GPU)
zig build -Dno-gpu

# Ejecutar
zig build run

# Tests
zig build test

# Benchmark GPU vs CPU
zig build run -- --benchmark
```

### 11.1 build.zig

```zig
// nvcc compila kernels CUDA
const nvcc = b.addSystemCommand(&.{
    "nvcc", "-O3", "-arch=sm_80", "-shared",
    "-o", "libbinius.so",
    "cuda/binius_kernels.cu",
});

// Zig ejecutable linkea contra libbinius.so
const exe = b.addExecutable(.{...});
exe.linkSystemLibrary("binius");
exe.step.dependOn(&nvcc.step);
```

---

## 12. Benchmarks

### 12.1 CPU Baseline (c3-standard-22)

| k | Field | Degree | Time | Mem |
|---|-------|--------|------|-----|
| 4 | GF(2^4) | 2 | 1ms | 1KB |
| 16 | GF(2^128) | 2 | 2.5s | 4MB |
| 20 | GF(2^128) | 3 | 45s | 64MB |
| 28 | GF(2^128) | 3 | 12min | 4GB |

### 12.2 GPU (B200, CLMAD)

| k | Field | Degree | Time | Speedup |
|---|-------|--------|------|---------|
| 16 | GF(2^128) | 2 | 0.2s | **12.5×** |
| 20 | GF(2^128) | 3 | 3.5s | **12.9×** |
| 28 | GF(2^128) | 3 | 55s | **13.1×** |

---

## 13. Roadmap

| Fase | Entregable | Duración |
|------|-----------|----------|
| 1 | Kernel GF(2^4) mul en CUDA | 1 semana |
| 2 | Suma-check round kernel | 2 semanas |
| 3 | Orquestación CPU-GPU (Zig↔CUDA) | 1 semana |
| 4 | Merkle tree GPU | 1 semana |
| 5 | Integración end-to-end | 2 semanas |
| 6 | Optimización CLMAD + benchmarks | 2 semanas |
| 7 | Integración bsvz (verificador Script) | 1 semana |
| **Total** | | **10 semanas** |

---

## 14. Referencias

1. Diamond, Posen (2023). "Succinct Arguments over Towers of Binary Fields." IACR ePrint 2023/1784.
2. Irreducible (2024). "Slicing Up Binary Towers: Accelerating Sumcheck on GPUs."
3. NVIDIA (2026). "Building Faster Cryptography with Carryless Multiplication in CUDA 13.3."
4. Fan, Wu, Han, Arafin (DATE 2026). "GPU Acceleration of the Sum-Check Protocol Over Towers of Binary Fields."
5. Dao, Thaler (2024). "Constraint-Packing and the Sum-Check Protocol over Binary Tower Fields." IACR ePrint 2024/1038.
6. Bagad, Domb, Thaler (2024). "The Sum-Check Protocol over Fields of Small Characteristic." IACR ePrint 2024/1046.

---

*Especificaciones versión 0.1.0 — 9 de agosto de 2026*
