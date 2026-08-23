/*
 * Guest CUDA application for the exact NVIDIA release gate.
 *
 * This program is intended to run INSIDE an Asterism guest/container. It
 * opens the projected local device (`/dev/nvidia0` by default) and the
 * injected libcuda (`ASTERISM_LIBCUDA` or libcuda.so.1), then drives a
 * small vector-add through the CUDA Driver API. Bytes are required to
 * cross two named mesh devices and execute on the provider helper.
 *
 * Compiling and running this on the provider host against a native
 * NVIDIA driver, without a guest projection and without the mesh, is
 * local-direct CUDA. That path cannot hardware-PASS the release gate.
 *
 * Expected output on success includes:
 *   guest_visible_device=/dev/nvidia0
 *   libcuda_path=...
 *   guest_output=6.0,2.0,6.0
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef CU_SUCCESS
#define CU_SUCCESS 0
#endif

typedef int CUresult;
typedef int CUdevice;
typedef struct CUctx_st *CUcontext;
typedef struct CUmod_st *CUmodule;
typedef struct CUfunc_st *CUfunction;
typedef unsigned long long CUdeviceptr;

typedef CUresult (*cuInit_t)(unsigned int);
typedef CUresult (*cuDeviceGet_t)(CUdevice *, int);
typedef CUresult (*cuCtxCreate_t)(CUcontext *, unsigned int, CUdevice);
typedef CUresult (*cuMemAlloc_t)(CUdeviceptr *, size_t);
typedef CUresult (*cuMemcpyHtoD_t)(CUdeviceptr, const void *, size_t);
typedef CUresult (*cuMemcpyDtoH_t)(void *, CUdeviceptr, size_t);
typedef CUresult (*cuModuleLoadData_t)(CUmodule *, const void *);
typedef CUresult (*cuModuleGetFunction_t)(CUfunction *, CUmodule, const char *);
typedef CUresult (*cuLaunchKernel_t)(CUfunction, unsigned, unsigned, unsigned,
                                     unsigned, unsigned, unsigned, unsigned,
                                     CUcontext, void **, void **);
typedef CUresult (*cuCtxSynchronize_t)(void);
typedef CUresult (*cuGetErrorString_t)(CUresult, const char **);

static const char *kPtx =
    ".version 7.0\n"
    ".target sm_50\n"
    ".address_size 64\n"
    "\n"
    ".visible .entry vector_add_f32(\n"
    "    .param .u64 lhs,\n"
    "    .param .u64 rhs,\n"
    "    .param .u64 output,\n"
    "    .param .u32 elements\n"
    ")\n"
    "{\n"
    "    .reg .pred %p;\n"
    "    .reg .b32 %r<6>;\n"
    "    .reg .b64 %rd<8>;\n"
    "    .reg .f32 %f<4>;\n"
    "    ld.param.u64 %rd1, [lhs];\n"
    "    ld.param.u64 %rd2, [rhs];\n"
    "    ld.param.u64 %rd3, [output];\n"
    "    ld.param.u32 %r1, [elements];\n"
    "    mov.u32 %r2, %ctaid.x;\n"
    "    mov.u32 %r3, %ntid.x;\n"
    "    mov.u32 %r4, %tid.x;\n"
    "    mad.lo.s32 %r5, %r2, %r3, %r4;\n"
    "    setp.ge.u32 %p, %r5, %r1;\n"
    "    @%p bra done;\n"
    "    mul.wide.u32 %rd4, %r5, 4;\n"
    "    add.s64 %rd5, %rd1, %rd4;\n"
    "    add.s64 %rd6, %rd2, %rd4;\n"
    "    add.s64 %rd7, %rd3, %rd4;\n"
    "    ld.global.f32 %f1, [%rd5];\n"
    "    ld.global.f32 %f2, [%rd6];\n"
    "    add.f32 %f3, %f1, %f2;\n"
    "    st.global.f32 [%rd7], %f3;\n"
    "done:\n"
    "    ret;\n"
    "}\n";

static void fail(const char *what) {
    fprintf(stderr, "GUEST CUDA FAIL: %s\n", what);
    exit(1);
}

int main(void) {
    const char *device_path = getenv("ASTERISM_GUEST_NVIDIA_DEVICE");
    if (device_path == NULL || device_path[0] == '\0') {
        device_path = "/dev/nvidia0";
    }
    const char *libcuda_path = getenv("ASTERISM_LIBCUDA");
    if (libcuda_path == NULL || libcuda_path[0] == '\0') {
        libcuda_path = "libcuda.so.1";
    }

    struct stat projected;
    if (stat(device_path, &projected) != 0 ||
        (!S_ISSOCK(projected.st_mode) && !S_ISCHR(projected.st_mode))) {
        fail("projected /dev/nvidia0 is not a local endpoint");
    }
    printf("guest_visible_device=%s\n", device_path);

    void *lib = dlopen(libcuda_path, RTLD_NOW);
    if (lib == NULL) {
        fprintf(stderr, "GUEST CUDA FAIL: dlopen %s: %s\n", libcuda_path, dlerror());
        return 1;
    }
    printf("libcuda_path=%s\n", libcuda_path);

#define LOAD(name, type)                                                       \
    type name = (type)dlsym(lib, #name);                                       \
    if (name == NULL) {                                                        \
        fail("dlsym " #name);                                                  \
    }

    LOAD(cuInit, cuInit_t);
    LOAD(cuDeviceGet, cuDeviceGet_t);
    LOAD(cuCtxCreate, cuCtxCreate_t);
    LOAD(cuMemAlloc, cuMemAlloc_t);
    LOAD(cuMemcpyHtoD, cuMemcpyHtoD_t);
    LOAD(cuMemcpyDtoH, cuMemcpyDtoH_t);
    LOAD(cuModuleLoadData, cuModuleLoadData_t);
    LOAD(cuModuleGetFunction, cuModuleGetFunction_t);
    LOAD(cuLaunchKernel, cuLaunchKernel_t);
    LOAD(cuCtxSynchronize, cuCtxSynchronize_t);
#undef LOAD

    if (cuInit(0) != CU_SUCCESS) {
        fail("cuInit");
    }
    CUdevice device = 0;
    if (cuDeviceGet(&device, 0) != CU_SUCCESS) {
        fail("cuDeviceGet");
    }
    CUcontext ctx = NULL;
    if (cuCtxCreate(&ctx, 0, device) != CU_SUCCESS) {
        fail("cuCtxCreate");
    }

    float lhs[3] = {1.0f, 2.5f, -4.0f};
    float rhs[3] = {5.0f, -0.5f, 10.0f};
    float out[3] = {0.0f, 0.0f, 0.0f};
    CUdeviceptr d_lhs = 0, d_rhs = 0, d_out = 0;
    if (cuMemAlloc(&d_lhs, sizeof(lhs)) != CU_SUCCESS ||
        cuMemAlloc(&d_rhs, sizeof(rhs)) != CU_SUCCESS ||
        cuMemAlloc(&d_out, sizeof(out)) != CU_SUCCESS) {
        fail("cuMemAlloc");
    }
    if (cuMemcpyHtoD(d_lhs, lhs, sizeof(lhs)) != CU_SUCCESS ||
        cuMemcpyHtoD(d_rhs, rhs, sizeof(rhs)) != CU_SUCCESS) {
        fail("cuMemcpyHtoD");
    }

    CUmodule module = NULL;
    CUfunction fn = NULL;
    if (cuModuleLoadData(&module, kPtx) != CU_SUCCESS) {
        fail("cuModuleLoadData");
    }
    if (cuModuleGetFunction(&fn, module, "vector_add_f32") != CU_SUCCESS) {
        fail("cuModuleGetFunction");
    }
    unsigned elements = 3;
    void *args[] = {&d_lhs, &d_rhs, &d_out, &elements};
    if (cuLaunchKernel(fn, 1, 1, 1, 32, 1, 1, 0, NULL, args, NULL) != CU_SUCCESS) {
        fail("cuLaunchKernel");
    }
    if (cuCtxSynchronize() != CU_SUCCESS) {
        fail("cuCtxSynchronize");
    }
    if (cuMemcpyDtoH(out, d_out, sizeof(out)) != CU_SUCCESS) {
        fail("cuMemcpyDtoH");
    }

    if (out[0] != 6.0f || out[1] != 2.0f || out[2] != 6.0f) {
        fprintf(stderr, "GUEST CUDA FAIL: got %f,%f,%f\n", out[0], out[1], out[2]);
        return 1;
    }
    printf("guest_output=6.0,2.0,6.0\n");
    printf("hardware_path=guest_libcuda_mesh\n");
    return 0;
}
