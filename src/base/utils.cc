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

int check_range_u2(const uint32_t value, const std::string& key) {
  if ((value < 0) | ((int)std::pow(2, 2) - 1 < value)) {
    LOG_ERROR("%s must be between 0-%d\n", key.c_str(),
              (int)std::pow(2, 2) - 1);
    return 1;
  }
  return 0;
}

int check_range_u4(const uint32_t value, const std::string& key) {
  if ((value < 0) | ((int)std::pow(2, 4) - 1 < value)) {
    LOG_ERROR("%s must be between 0-%d\n", key.c_str(),
              (int)std::pow(2, 4) - 1);
    return 1;
  }
  return 0;
}

int check_range_u6(const uint32_t value, const std::string& key) {
  if ((value < 0) | ((int)std::pow(2, 6) - 1 < value)) {
    LOG_ERROR("%s must be between 0-%d\n", key.c_str(),
              (int)std::pow(2, 6) - 1);
    return 1;
  }
  return 0;
}

int check_range_u8(const uint32_t value, const std::string& key) {
  if ((value < 0) | ((int)std::pow(2, 8) - 1 < value)) {
    LOG_ERROR("%s must be between 0-%d\n", key.c_str(),
              (int)std::pow(2, 8) - 1);
    return 1;
  }
  return 0;
}

int check_range_u16(const uint32_t value, const std::string& key) {
  if ((value < 0) | ((int)std::pow(2, 16) - 1 < value)) {
    LOG_ERROR("%s must be between 0-%d\n", key.c_str(),
              (int)std::pow(2, 16) - 1);
    return 1;
  }
  return 0;
}

int check_range_u32(const uint64_t value, const std::string& key) {
  if ((value < 0) | ((int)std::pow(2, 32) - 1 < value)) {
    LOG_ERROR("%s must be between 0-%d\n", key.c_str(),
              (int)std::pow(2, 32) - 1);
    return 1;
  }
  return 0;
}
