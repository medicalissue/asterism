/*
 * In-guest CUDA Driver API client for the projected /dev/nvidia0 part.
 *
 * This is an ordinary CUDA application: it resolves `libcuda.so.1` through
 * the dynamic loader, calls only documented CUDA Driver API entry points,
 * and knows nothing about Asterism, the provider host, the mesh, or any
 * lease. Inside an attached Asterism instance the loader resolves the
 * injected shim, so every call below leaves the guest through
 * /dev/nvidia0 and is executed by the provider device's GPU.
 *
 * Build (any Linux with a C compiler):
 *   cc -o asterism-guest-vector-add remote_gpu_guest_vector_add.c -ldl
 *
 * Run inside the guest:
 *   ./asterism-guest-vector-add            # 4 elements, the pinned kernel
 *   ./asterism-guest-vector-add 65536 20   # elements, iterations
 *
 * It prints the returned floats plus per-iteration latency so the caller
 * can file real numbers instead of an exit code.
 */

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef int CUresult;
typedef int CUdevice;
typedef unsigned long long CUdeviceptr;

#define CUDA_SUCCESS 0
#define CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR 75
#define CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR 76
#define CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT 16

/* The exact content-pinned PTX ABI 1 admits. Byte-for-byte identical to
 * asterism_core::remote_gpu::VECTOR_ADD_PTX; the provider verifies its
 * BLAKE3 pin before it will launch anything. */
static const char VECTOR_ADD_PTX[] =
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

static void *driver;

static void *entry(const char *name) {
  void *symbol = dlsym(driver, name);
  if (symbol == NULL) {
    fprintf(stderr, "libcuda.so.1 does not export %s\n", name);
    exit(1);
  }
  return symbol;
}

static CUresult (*cu_init)(unsigned int);
static CUresult (*cu_driver_get_version)(int *);
static CUresult (*cu_device_get_count)(int *);
static CUresult (*cu_device_get)(CUdevice *, int);
static CUresult (*cu_device_get_name)(char *, int, CUdevice);
static CUresult (*cu_device_get_uuid)(char *, CUdevice);
static CUresult (*cu_device_get_attribute)(int *, int, CUdevice);
static CUresult (*cu_ctx_create)(void **, unsigned int, CUdevice);
static CUresult (*cu_ctx_get_current)(void **);
static CUresult (*cu_ctx_set_current)(void *);
static CUresult (*cu_ctx_synchronize)(void);
static CUresult (*cu_ctx_destroy)(void *);
static CUresult (*cu_mem_alloc)(CUdeviceptr *, size_t);
static CUresult (*cu_mem_free)(CUdeviceptr);
static CUresult (*cu_memcpy_htod)(CUdeviceptr, const void *, size_t);
static CUresult (*cu_memcpy_dtoh)(void *, CUdeviceptr, size_t);
static CUresult (*cu_module_load_data)(void **, const void *);
static CUresult (*cu_module_unload)(void *);
static CUresult (*cu_module_get_function)(void **, void *, const char *);
static CUresult (*cu_launch_kernel)(void *, unsigned int, unsigned int,
                                    unsigned int, unsigned int, unsigned int,
                                    unsigned int, unsigned int, void *,
                                    void **, void **);
static CUresult (*cu_get_error_name)(int, const char **);
static CUresult (*cu_get_error_string)(int, const char **);

static void check(CUresult status, const char *what) {
  if (status == CUDA_SUCCESS) {
    return;
  }
  const char *name = NULL;
  const char *text = NULL;
  if (cu_get_error_name != NULL) {
    cu_get_error_name(status, &name);
  }
  if (cu_get_error_string != NULL) {
    cu_get_error_string(status, &text);
  }
  fprintf(stderr, "%s failed: %d (%s: %s)\n", what, status,
          name != NULL ? name : "?", text != NULL ? text : "?");
  exit(1);
}

static double now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1.0e6;
}

static int compare(const void *left, const void *right) {
  double a = *(const double *)left;
  double b = *(const double *)right;
  return a < b ? -1 : (a > b ? 1 : 0);
}

int main(int argc, char **argv) {
  unsigned int elements = argc > 1 ? (unsigned int)strtoul(argv[1], NULL, 10) : 4u;
  unsigned int iterations = argc > 2 ? (unsigned int)strtoul(argv[2], NULL, 10) : 1u;
  if (elements == 0 || iterations == 0) {
    fprintf(stderr, "elements and iterations must both be positive\n");
    return 2;
  }

  driver = dlopen("libcuda.so.1", RTLD_NOW);
  if (driver == NULL) {
    fprintf(stderr, "could not load libcuda.so.1: %s\n", dlerror());
    return 1;
  }

  cu_init = entry("cuInit");
  cu_driver_get_version = entry("cuDriverGetVersion");
  cu_device_get_count = entry("cuDeviceGetCount");
  cu_device_get = entry("cuDeviceGet");
  cu_device_get_name = entry("cuDeviceGetName");
  cu_device_get_uuid = entry("cuDeviceGetUuid");
  cu_device_get_attribute = entry("cuDeviceGetAttribute");
  cu_ctx_create = entry("cuCtxCreate_v2");
  cu_ctx_get_current = entry("cuCtxGetCurrent");
  cu_ctx_set_current = entry("cuCtxSetCurrent");
  cu_ctx_synchronize = entry("cuCtxSynchronize");
  cu_ctx_destroy = entry("cuCtxDestroy_v2");
  cu_mem_alloc = entry("cuMemAlloc_v2");
  cu_mem_free = entry("cuMemFree_v2");
  cu_memcpy_htod = entry("cuMemcpyHtoD_v2");
  cu_memcpy_dtoh = entry("cuMemcpyDtoH_v2");
  cu_module_load_data = entry("cuModuleLoadData");
  cu_module_unload = entry("cuModuleUnload");
  cu_module_get_function = entry("cuModuleGetFunction");
  cu_launch_kernel = entry("cuLaunchKernel");
  cu_get_error_name = entry("cuGetErrorName");
  cu_get_error_string = entry("cuGetErrorString");

  check(cu_init(0), "cuInit");

  int driver_version = 0;
  check(cu_driver_get_version(&driver_version), "cuDriverGetVersion");
  int count = 0;
  check(cu_device_get_count(&count), "cuDeviceGetCount");
  if (count < 1) {
    fprintf(stderr, "no CUDA device behind /dev/nvidia0\n");
    return 1;
  }
  CUdevice device = 0;
  check(cu_device_get(&device, 0), "cuDeviceGet");
  char name[256];
  memset(name, 0, sizeof(name));
  check(cu_device_get_name(name, (int)sizeof(name) - 1, device),
        "cuDeviceGetName");
  unsigned char uuid[16];
  memset(uuid, 0, sizeof(uuid));
  check(cu_device_get_uuid((char *)uuid, device), "cuDeviceGetUuid");
  int major = 0;
  int minor = 0;
  int sms = 0;
  check(cu_device_get_attribute(
            &major, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, device),
        "cuDeviceGetAttribute(cc major)");
  check(cu_device_get_attribute(
            &minor, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, device),
        "cuDeviceGetAttribute(cc minor)");
  check(cu_device_get_attribute(&sms, CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT,
                                device),
        "cuDeviceGetAttribute(sm count)");

  void *context = NULL;
  check(cu_ctx_create(&context, 0, device), "cuCtxCreate");
  void *current = NULL;
  check(cu_ctx_get_current(&current), "cuCtxGetCurrent");
  check(cu_ctx_set_current(context), "cuCtxSetCurrent");

  size_t bytes = (size_t)elements * sizeof(float);
  float *lhs = malloc(bytes);
  float *rhs = malloc(bytes);
  float *out = malloc(bytes);
  if (lhs == NULL || rhs == NULL || out == NULL) {
    fprintf(stderr, "host allocation of %zu bytes failed\n", bytes);
    return 1;
  }
  for (unsigned int i = 0; i < elements; i++) {
    lhs[i] = (float)(i % 97) + 0.5f;
    rhs[i] = (float)(i % 31) * 2.0f;
  }

  CUdeviceptr d_lhs = 0;
  CUdeviceptr d_rhs = 0;
  CUdeviceptr d_out = 0;
  check(cu_mem_alloc(&d_lhs, bytes), "cuMemAlloc(lhs)");
  check(cu_mem_alloc(&d_rhs, bytes), "cuMemAlloc(rhs)");
  check(cu_mem_alloc(&d_out, bytes), "cuMemAlloc(out)");

  void *module = NULL;
  check(cu_module_load_data(&module, VECTOR_ADD_PTX), "cuModuleLoadData");
  void *function = NULL;
  check(cu_module_get_function(&function, module, "vector_add_f32"),
        "cuModuleGetFunction");

  double *samples = malloc(sizeof(double) * iterations);
  if (samples == NULL) {
    fprintf(stderr, "sample allocation failed\n");
    return 1;
  }

  unsigned int block = 256;
  unsigned int grid = (elements + block - 1) / block;
  for (unsigned int iteration = 0; iteration < iterations; iteration++) {
    double started = now_ms();
    check(cu_memcpy_htod(d_lhs, lhs, bytes), "cuMemcpyHtoD(lhs)");
    check(cu_memcpy_htod(d_rhs, rhs, bytes), "cuMemcpyHtoD(rhs)");
    void *params[4];
    params[0] = &d_lhs;
    params[1] = &d_rhs;
    params[2] = &d_out;
    params[3] = &elements;
    check(cu_launch_kernel(function, grid, 1, 1, block, 1, 1, 0, NULL, params,
                           NULL),
          "cuLaunchKernel");
    check(cu_ctx_synchronize(), "cuCtxSynchronize");
    check(cu_memcpy_dtoh(out, d_out, bytes), "cuMemcpyDtoH");
    samples[iteration] = now_ms() - started;
  }

  for (unsigned int i = 0; i < elements; i++) {
    float expected = lhs[i] + rhs[i];
    if (out[i] != expected) {
      fprintf(stderr, "element %u is %f, expected %f\n", i, (double)out[i],
              (double)expected);
      return 1;
    }
  }

  qsort(samples, iterations, sizeof(double), compare);
  double p50 = samples[iterations / 2];
  double p95 = samples[(iterations * 95) / 100 >= iterations
                           ? iterations - 1
                           : (iterations * 95) / 100];
  double moved_mib = ((double)bytes * 3.0) / (1024.0 * 1024.0);
  double throughput = p50 > 0.0 ? moved_mib / (p50 / 1000.0) : 0.0;

  printf("guest_visible_device=/dev/nvidia0\n");
  printf("resolved_driver=libcuda.so.1\n");
  printf("cuda_driver_version=%d\n", driver_version);
  printf("device_count=%d\n", count);
  printf("device_name=%s\n", name);
  printf("device_uuid=GPU-");
  for (int i = 0; i < 16; i++) {
    printf("%02x", uuid[i]);
    if (i == 3 || i == 5 || i == 7 || i == 9) {
      printf("-");
    }
  }
  printf("\n");
  printf("compute_capability=%d.%d\n", major, minor);
  printf("multiprocessor_count=%d\n", sms);
  printf("elements=%u\n", elements);
  printf("iterations=%u\n", iterations);
  printf("first_four=[");
  for (unsigned int i = 0; i < 4 && i < elements; i++) {
    printf("%s%.1f", i == 0 ? "" : ", ", (double)out[i]);
  }
  printf("]\n");
  printf("e2e_p50_ms=%.3f\n", p50);
  printf("e2e_p95_ms=%.3f\n", p95);
  printf("payload_mib_per_iteration=%.3f\n", moved_mib);
  printf("throughput_mib_s=%.2f\n", throughput);
  printf("result=verified\n");

  check(cu_module_unload(module), "cuModuleUnload");
  check(cu_mem_free(d_lhs), "cuMemFree(lhs)");
  check(cu_mem_free(d_rhs), "cuMemFree(rhs)");
  check(cu_mem_free(d_out), "cuMemFree(out)");
  check(cu_ctx_destroy(context), "cuCtxDestroy");
  free(lhs);
  free(rhs);
  free(out);
  free(samples);
  (void)current;
  return 0;
}
