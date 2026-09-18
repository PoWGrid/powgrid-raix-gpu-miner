#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int cuda_bridge_get_device_count();
int cuda_bridge_get_device_info(int device_id, char* name_out, size_t name_len, size_t* total_mem, int* sm_count, int* major, int* minor);
void* cuda_bridge_worker_create(int device_id, int total_threads, int nonces_per_thread);
void cuda_bridge_worker_destroy(void* handle);
int cuda_bridge_worker_run_batch(
    void* handle,
    const char* prefix, int prefix_len,
    const char* suffix, int suffix_len,
    const char* seed, int seed_len,
    uint64_t target_u64,
    int target_diff,
    uint64_t base_nonce,
    uint64_t* found_nonces_out,
    int max_found,
    int* found_count_out,
    uint64_t* hashes_done_out
);
int cuda_bridge_self_test(int device_id);

#ifdef __cplusplus
}
#endif
