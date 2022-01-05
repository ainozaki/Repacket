#ifndef BINARY_UTILS_H_
#define BINARY_UTILS_H_

#include <arpa/inet.h>
#include <stdint.h>

static inline uint8_t GET_U8(const void *p)
{
	return *(uint8_t *)p;
}

static inline uint16_t GET_U16(const void *p)
{
	return (uint16_t)ntohs(*(const uint16_t *)(p));
}

#endif // BINARY_UTILS_H_
