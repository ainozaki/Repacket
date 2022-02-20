#include "base/utils.h"

#include <cmath>
#include <string>

#include "base/logger.h"

int check_range_ipaddr(std::string s) {
  uint32_t addr = 0;
  size_t pos;
  std::string delemiter = ".";

  s += ".";
  for (int i = 0; i < 4; i++) {
    size_t pos = s.find(delemiter);
    if (pos == std::string::npos) {
      LOG_ERROR("Invalid ip address format.\n");
      return 1;
    }
    uint16_t sub = std::stoi(s.substr(0, pos));
    if (sub<0 | sub> 255) {
      LOG_ERROR("Invalid ip address value.\n");
      return 1;
    }
    s.erase(0, pos + delemiter.length());
    // Future.
    addr += pow(2, i * 8) * sub;
  }
  return 0;
}

int check_range_u4(const uint8_t value, const std::string& key) {
  if ((value < 0) | (31 < value)) {
    LOG_ERROR("%s must be between 0-31.\n", key.c_str());
    return 1;
  }
  return 0;
}

int check_range_u8(const uint16_t value, const std::string& key) {
  if ((value < 0) | (255 < value)) {
    LOG_ERROR("%s must be between 0-255.\n", key.c_str());
    return 1;
  }
  return 0;
}

int check_range_u16(const uint32_t value, const std::string& key) {
  if ((value < 0) | (65535 < value)) {
    LOG_ERROR("%s must be between 0-65535.\n", key.c_str());
    return 1;
  }
  return 0;
}

int check_range_u32(const uint64_t value, const std::string& key) {
  if ((value < 0) | (std::pow(2, 32) - 1 < value)) {
    LOG_ERROR("%s must be between 0-4294967295.\n", key.c_str());
    return 1;
  }
  return 0;
}
