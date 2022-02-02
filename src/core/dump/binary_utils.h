#ifndef BINARY_UTILS_H_
#define BINARY_UTILS_H_

#include <cstdint>

#include "core/dump/types.h"

// Get each size of int from pointer.
// Pass pointer with network-order, since this handles byte-order inside.
uint8_t GET_U8(const void* p);
uint16_t GET_U16(const void* p);

// Get formatted address from pointer.
char* GET_IPADDR(const void* p);
char* GET_ETHADDR(const void* p);

#endif  // BINARY_UTILS_H_
