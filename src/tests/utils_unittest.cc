#include "gtest/gtest.h"

#include <cmath>
#include <string>

#include "base/utils.h"

TEST(Utils, RungeU2) {
  int key_ok_min = 0;
  int key_ok_max = 3;
  int key_ng_min = -1;
  int key_ng_max = 4;
  int err_ok_min = check_range_u2(key_ok_min, "key_ok_min");
  int err_ok_max = check_range_u2(key_ok_max, "key_ok_max");
  int err_ng_min = check_range_u2(key_ng_min, "key_ng_min");
  int err_ng_max = check_range_u2(key_ng_max, "key_ng_max");
  EXPECT_EQ(0, err_ok_min);
  EXPECT_EQ(0, err_ok_max);
  EXPECT_EQ(1, err_ng_min);
  EXPECT_EQ(1, err_ng_max);
}

TEST(Utils, RungeU4) {
  int key_ok_min = 0;
  int key_ok_max = 15;
  int key_ng_min = -1;
  int key_ng_max = 16;
  int err_ok_min = check_range_u4(key_ok_min, "key_ok_min");
  int err_ok_max = check_range_u4(key_ok_max, "key_ok_max");
  int err_ng_min = check_range_u4(key_ng_min, "key_ng_min");
  int err_ng_max = check_range_u4(key_ng_max, "key_ng_max");
  EXPECT_EQ(0, err_ok_min);
  EXPECT_EQ(0, err_ok_max);
  EXPECT_EQ(1, err_ng_min);
  EXPECT_EQ(1, err_ng_max);
}

TEST(Utils, RungeU6) {
  int key_ok_min = 0;
  int key_ok_max = 63;
  int key_ng_min = -1;
  int key_ng_max = 64;
  int err_ok_min = check_range_u6(key_ok_min, "key_ok_min");
  int err_ok_max = check_range_u6(key_ok_max, "key_ok_max");
  int err_ng_min = check_range_u6(key_ng_min, "key_ng_min");
  int err_ng_max = check_range_u6(key_ng_max, "key_ng_max");
  EXPECT_EQ(0, err_ok_min);
  EXPECT_EQ(0, err_ok_max);
  EXPECT_EQ(1, err_ng_min);
  EXPECT_EQ(1, err_ng_max);
}

TEST(Utils, RungeU8) {
  int key_ok_min = 0;
  int key_ok_max = 255;
  int key_ng_min = -1;
  int key_ng_max = 256;
  int err_ok_min = check_range_u8(key_ok_min, "key_ok_min");
  int err_ok_max = check_range_u8(key_ok_max, "key_ok_max");
  int err_ng_min = check_range_u8(key_ng_min, "key_ng_min");
  int err_ng_max = check_range_u8(key_ng_max, "key_ng_max");
  EXPECT_EQ(0, err_ok_min);
  EXPECT_EQ(0, err_ok_max);
  EXPECT_EQ(1, err_ng_min);
  EXPECT_EQ(1, err_ng_max);
}

TEST(Utils, RungeU16) {
  int key_ok_min = 0;
  int key_ok_max = (int)std::pow(2, 16) - 1;
  int key_ng_min = -1;
  int key_ng_max = (int)std::pow(2, 16);
  int err_ok_min = check_range_u16(key_ok_min, "key_ok_min");
  int err_ok_max = check_range_u16(key_ok_max, "key_ok_max");
  int err_ng_min = check_range_u16(key_ng_min, "key_ng_min");
  int err_ng_max = check_range_u16(key_ng_max, "key_ng_max");
  EXPECT_EQ(0, err_ok_min);
  EXPECT_EQ(0, err_ok_max);
  EXPECT_EQ(1, err_ng_min);
  EXPECT_EQ(1, err_ng_max);
}

TEST(Utils, RungeU32) {
  int64_t key_ok_min = 0;
  int64_t key_ok_max = (int)std::pow(2, 32) - 1;
  int64_t key_ng_min = -1;
  int64_t key_ng_max = (int)std::pow(2, 32);
  int err_ok_min = check_range_u32(key_ok_min, "key_ok_min");
  int err_ok_max = check_range_u32(key_ok_max, "key_ok_max");
  int err_ng_min = check_range_u32(key_ng_min, "key_ng_min");
  int err_ng_max = check_range_u32(key_ng_max, "key_ng_max");
  EXPECT_EQ(0, err_ok_min);
  EXPECT_EQ(0, err_ok_max);
  EXPECT_EQ(1, err_ng_min);
  EXPECT_EQ(1, err_ng_max);
}
