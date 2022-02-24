#ifndef UTILS_H_
#define UTILS_H_

#include <string>

int check_range_ipaddr(std::string s);

int check_range_u2(const uint32_t value, const std::string& key);
int check_range_u4(const uint32_t value, const std::string& key);
int check_range_u6(const uint32_t value, const std::string& key);
int check_range_u8(const uint32_t value, const std::string& key);
int check_range_u16(const uint32_t value, const std::string& key);
int check_range_u32(const uint64_t value, const std::string& key);

#endif  // UTILS_H_
