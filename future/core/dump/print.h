#ifndef PRINT_H_
#define PRINT_H_

#include <cstdint>

#include "base/config.h"

void StartDump(struct config& config, const unsigned char* p, uint8_t len);

// Forward declaration of xxxPrint()
// There functions are defined in print-xxx.c
void ArpPrint(const unsigned char* p, uint8_t len);
void EtherPrint(const unsigned char* p, uint8_t len);
void IpPrint(const unsigned char* p, uint8_t len);
void IcmpPrint(const unsigned char* p, uint8_t len);
void TcpPrint(const unsigned char* p, uint8_t len);
void UdpPrint(const unsigned char* p, uint8_t len);

void ether_friendlyPrint(const unsigned char* p, uint8_t len);
void ip_friendlyPrint(const unsigned char* p, uint8_t len);
void icmp_friendlyPrint(const unsigned char* p, uint8_t len);
#endif  // PRINT_H_
