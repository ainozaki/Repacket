#ifndef PRINT_H_
#define PRINT_H_

#include <stdint.h>

void start_dump(const unsigned char* p, uint8_t len);

// Forward declaration of xxx_print()
// There functions are defined in print-xxx.c
void arp_print(const unsigned char* p, uint8_t len);
void ether_print(const unsigned char* p, uint8_t len);
void ip_print(const unsigned char* p, uint8_t len);
void icmp_print(const unsigned char* p, uint8_t len);

#endif  // PRINT_H_
