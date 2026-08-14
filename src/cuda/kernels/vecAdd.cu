// Elementwise u32 addition — the E0a toolchain validation kernel.
// Regenerate the PTX with: nvcc -ptx -arch=sm_86 -o vecAdd.ptx vecAdd.cu
extern "C" __global__ void vecAdd(unsigned int* out, const unsigned int* a, const unsigned int* b, unsigned int n) {
    unsigned int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) out[i] = a[i] + b[i];
}
