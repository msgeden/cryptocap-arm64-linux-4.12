#ifndef __ASM_CRYPTOCAP_H
#define __ASM_CRYPTOCAP_H
#include <stddef.h>
#include <linux/types.h>
#include <linux/printk.h>

//#include <stdint.h>
#include <stdbool.h>

#define CC_CAP_THRESHOLD_SIZE 1024*1024


/* Capability operations */

void cc_store_cap_from_CR0(cc_dcap* cap);
cc_dcap cc_create_signed_cap_on_CR0(const void* base, size_t offset, size_t size, bool write_flag);

void cc_load_ver_cap_to_CR0(cc_dcap* cap);
uint8_t* cc_memcpy_i8(void* dst, cc_dcap src, size_t count);
void cc_print_cap(cc_dcap cap);

#endif