#ifndef BINARY_UTILS_H_
#define BINARY_UTILS_H_

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

static inline uint8_t GET_U8(const void* p) {
  return *(uint8_t*)p;
}

static inline uint16_t GET_U16(const void* p) {
  return (uint16_t)ntohs(*(const uint16_t*)(p));
}

static inline char* GET_IPADDR(const void* p) {
  char buf[32];
  char* ptr;
  // inet_ntop expects network-order binary.
  inet_ntop(AF_INET, (struct in_addr*)p, buf, sizeof(buf));
  ptr = buf;
  // TODO: buf address is the same for every call. why?
  // printf("buf ptr: %p\n", buf);
  return ptr;
}

#endif  // BINARY_UTILS_H_
