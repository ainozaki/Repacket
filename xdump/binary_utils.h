#ifndef BINARY_UTILS_H_
#define BINARY_UTILS_H_

#include <arpa/inet.h>
#include <stdint.h>

static inline uint16_t CONVERT_U16(const void *p)
{
	return (uint16_t)ntohs(*(const uint16_t *)(p));
}

#endif // BINARY_UTILS_H_
