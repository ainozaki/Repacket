#ifndef UTILS_H_
#define UTILS_H_

#include <string>

uint32_t ipaddr_from_string(std::string s);

int check_range_u4(const uint8_t value, const std::string& key);

int check_range_u8(const uint16_t value, const std::string& key);

int check_range_u16(const uint32_t value, const std::string& key);

int check_range_u32(const uint64_t value, const std::string& key);

#endif  // UTILS_H_
