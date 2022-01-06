#ifndef PRINT_ETHER_H_
#define PRINT_ETHER_H_

#include <stdint.h>

void start_dump(const unsigned char* p, uint8_t len);

void ether_print(const unsigned char* p, uint8_t len);

#endif  // PRINT_ETHER_H_
