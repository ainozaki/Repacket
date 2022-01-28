#include "core/dump/binary_utils.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/dump/def/types.h"

// static functions

static const char* ipaddr_to_string(uint32_t addr) {
  char* cp;
  u_int byte;
  int n;
  static char buf[sizeof(".xxx.xxx.xxx.xxx")];

  // ntohl expects network-order binary.
  addr = ntohl(addr);
  cp = buf + sizeof(buf);
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = (char)(byte % 10) + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = (char)(byte % 10) + '0';
      byte /= 10;
      if (byte > 0)
        *--cp = (char)byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  return cp + 1;
}

static int hex_to_ascii(uint8_t n) {
  if (n < 10) {
    return (char)n + '0';
  } else {
    return 'a' + n - 10;
  }
}

static const char* ethaddr_to_string(n_uint48_t addr) {
  char* cp;
  uint8_t byte;
  int n;
  static char buf[sizeof("xx:xx:xx:xx:xx:xx")];

  cp = buf + sizeof(buf);
  *--cp = '\0';

  n = 6;
  do {
    byte = (uint8_t)addr[n - 1];
    *--cp = hex_to_ascii(byte % 16);
    byte /= 16;
    if (byte > 0) {
      *--cp = hex_to_ascii(byte % 16);
    }
    *--cp = ':';
  } while (--n > 0);

  return cp + 1;
}

// GET_XXADDR

char* GET_ETHADDR(const void* p) {
  char* ptr;
  n_uint48_t addr;

  memcpy(&addr, p, sizeof(addr));
  ptr = strdup(ethaddr_to_string(addr));
  return ptr;
}

char* GET_IPADDR(const void* p) {
  char* ptr;
  uint32_t addr;

  memcpy(&addr, p, sizeof(addr));
  ptr = strdup(ipaddr_to_string(addr));
  return ptr;
}

// GET_UXX

uint8_t GET_U8(const void* p) {
  return *(uint8_t*)p;
}

uint16_t GET_U16(const void* p) {
  return (uint16_t)ntohs(*(const uint16_t*)(p));
}
