/* Tiny two-device CUDA vector-add used by the paid NVIDIA hardware gate.
 *
 * This is evidence, not a product CUDA runtime. The production guest still
 * sees /dev/nvidia0 through the ABI; this program only proves a host can
 * enumerate a device, copy buffers, launch a kernel, and read the result.
 *
 * Usage: remote_gpu_vector_add <device-index>
 * Exit 0 only when the selected device produced 6.0, 2.0, 6.0.
 */
#include <cuda_runtime.h>
#include <stdio.h>
#include <stdlib.h>

__global__ void vector_add_f32(const float *lhs, const float *rhs, float *out, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) {
        out[i] = lhs[i] + rhs[i];
    }
}

static void fail(const char *what, cudaError_t err) {
    fprintf(stderr, "CUDA FAIL: %s: %s\n", what, cudaGetErrorString(err));
    exit(1);
}

int main(int argc, char **argv) {
    int device = 0;
    if (argc > 1) {
        device = atoi(argv[1]);
    }
    int count = 0;
    cudaError_t err = cudaGetDeviceCount(&count);
    if (err != cudaSuccess) {
        fail("cudaGetDeviceCount", err);
    }
    if (count < 2) {
        fprintf(stderr, "CUDA FAIL: need 2 devices, saw %d\n", count);
        return 1;
    }
    if (device < 0 || device >= count) {
        fprintf(stderr, "CUDA FAIL: device %d out of range 0..%d\n", device, count - 1);
        return 1;
    }
    err = cudaSetDevice(device);
    if (err != cudaSuccess) {
        fail("cudaSetDevice", err);
    }

    struct cudaDeviceProp prop;
    err = cudaGetDeviceProperties(&prop, device);
    if (err != cudaSuccess) {
        fail("cudaGetDeviceProperties", err);
    }
    printf("cuda_device_index=%d\n", device);
    printf("cuda_device_name=%s\n", prop.name);
    printf("cuda_compute_capability=%d.%d\n", prop.major, prop.minor);

    const int n = 3;
    const size_t bytes = (size_t)n * sizeof(float);
    float host_lhs[] = {1.0f, 2.5f, -4.0f};
    float host_rhs[] = {5.0f, -0.5f, 10.0f};
    float host_out[] = {0.0f, 0.0f, 0.0f};
    float *dev_lhs = NULL;
    float *dev_rhs = NULL;
    float *dev_out = NULL;
    if ((err = cudaMalloc((void **)&dev_lhs, bytes)) != cudaSuccess) fail("cudaMalloc lhs", err);
    if ((err = cudaMalloc((void **)&dev_rhs, bytes)) != cudaSuccess) fail("cudaMalloc rhs", err);
    if ((err = cudaMalloc((void **)&dev_out, bytes)) != cudaSuccess) fail("cudaMalloc out", err);
    if ((err = cudaMemcpy(dev_lhs, host_lhs, bytes, cudaMemcpyHostToDevice)) != cudaSuccess) {
        fail("cudaMemcpy lhs", err);
    }
    if ((err = cudaMemcpy(dev_rhs, host_rhs, bytes, cudaMemcpyHostToDevice)) != cudaSuccess) {
        fail("cudaMemcpy rhs", err);
    }
    vector_add_f32<<<1, 32>>>(dev_lhs, dev_rhs, dev_out, n);
    if ((err = cudaGetLastError()) != cudaSuccess) fail("kernel launch", err);
    if ((err = cudaDeviceSynchronize()) != cudaSuccess) fail("synchronize", err);
    if ((err = cudaMemcpy(host_out, dev_out, bytes, cudaMemcpyDeviceToHost)) != cudaSuccess) {
        fail("cudaMemcpy out", err);
    }
    cudaFree(dev_lhs);
    cudaFree(dev_rhs);
    cudaFree(dev_out);

    printf("cuda_kernel=vector_add_f32\n");
    printf("cuda_result=%g,%g,%g\n", host_out[0], host_out[1], host_out[2]);
    if (host_out[0] != 6.0f || host_out[1] != 2.0f || host_out[2] != 6.0f) {
        fprintf(stderr, "CUDA FAIL: unexpected vector-add result\n");
        return 1;
    }
    printf("cuda_verified=true\n");
    return 0;
}
