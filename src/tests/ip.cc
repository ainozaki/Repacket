#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "base/define/define.h"
#include "core/loader/loader.h"
#include "core/stats/stats.h"

TEST(IPTest, FilterByProtocol) {
  config cfg;
  cfg.mode = Mode::Attach;
  cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
  cfg.ifindex = if_nametoindex("veth1");
  cfg.ifname = "veth1";
  cfg.bpf_filepath = "filter-test/xdp_test_ip_protocol.o";
  cfg.progsec = "xdp_generated";
  Loader loader(cfg.mode, cfg.xdp_flags, cfg.ifindex, cfg.ifname,
                cfg.bpf_filepath, cfg.progsec);
  loader.Start();

  system(
      "/usr/bin/bash /home/aino/Projects/xapture/xilter/filter-test/ip.sh "
      "ip_protocol");

  Stats stats("veth1", "filter-test/ip_protocol.yaml");
  __u32 key = 1;
  datarec value1 = stats.GetMapValueForTesting(key);
  key++;
  datarec value2 = stats.GetMapValueForTesting(key);
  key++;
  datarec value3 = stats.GetMapValueForTesting(key);
  EXPECT_EQ(1, value1.rx_packets);
  EXPECT_EQ(2, value2.rx_packets);
  EXPECT_EQ(3, value3.rx_packets);

  loader.DetachBpf();
}

TEST(IPTest, FilterBySaddr) {
  config cfg;
  cfg.mode = Mode::Attach;
  cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
  cfg.ifindex = if_nametoindex("veth1");
  cfg.ifname = "veth1";
  cfg.bpf_filepath = "filter-test/xdp_test_ip_saddr.o";
  cfg.progsec = "xdp_generated";
  Loader loader(cfg.mode, cfg.xdp_flags, cfg.ifindex, cfg.ifname,
                cfg.bpf_filepath, cfg.progsec);
  loader.Start();

  system(
      "/usr/bin/bash /home/aino/Projects/xapture/xilter/filter-test/ip.sh "
      "ip_saddr");

  Stats stats("veth1", "filter-test/ip_saddr.yaml");
  __u32 key = 1;
  datarec value1 = stats.GetMapValueForTesting(key);
  key++;
  datarec value2 = stats.GetMapValueForTesting(key);
  key++;
  datarec value3 = stats.GetMapValueForTesting(key);
  key++;
  datarec value4 = stats.GetMapValueForTesting(key);
  key++;
  datarec value5 = stats.GetMapValueForTesting(key);
  EXPECT_EQ(1, value1.rx_packets);
  EXPECT_EQ(2, value2.rx_packets);
  EXPECT_EQ(3, value3.rx_packets);
  EXPECT_EQ(4, value4.rx_packets);
  EXPECT_EQ(5, value5.rx_packets);

  loader.DetachBpf();
}

TEST(IPTest, FilterByToS) {
  config cfg;
  cfg.mode = Mode::Attach;
  cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
  cfg.ifindex = if_nametoindex("veth1");
  cfg.ifname = "veth1";
  cfg.bpf_filepath = "filter-test/xdp_test_ip_tos.o";
  cfg.progsec = "xdp_generated";
  Loader loader(cfg.mode, cfg.xdp_flags, cfg.ifindex, cfg.ifname,
                cfg.bpf_filepath, cfg.progsec);
  loader.Start();

  system(
      "/usr/bin/bash /home/aino/Projects/xapture/xilter/filter-test/ip.sh "
      "ip_tos");

  Stats stats("veth1", "filter-test/ip_tos.yaml");
  __u32 key = 1;
  datarec value1 = stats.GetMapValueForTesting(key);
  key++;
  datarec value2 = stats.GetMapValueForTesting(key);
  key++;
  datarec value3 = stats.GetMapValueForTesting(key);
  key++;
  datarec value4 = stats.GetMapValueForTesting(key);
  key++;
  datarec value5 = stats.GetMapValueForTesting(key);
  EXPECT_EQ(1, value1.rx_packets);
  EXPECT_EQ(2, value2.rx_packets);
  EXPECT_EQ(3, value3.rx_packets);
  EXPECT_EQ(4, value4.rx_packets);
  EXPECT_EQ(5, value5.rx_packets);

  loader.DetachBpf();
}

TEST(IPTest, FilterByTTLMin) {
  config cfg;
  cfg.mode = Mode::Attach;
  cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
  cfg.ifindex = if_nametoindex("veth1");
  cfg.ifname = "veth1";
  cfg.bpf_filepath = "filter-test/xdp_test_ip_ttl_min.o";
  cfg.progsec = "xdp_generated";
  Loader loader(cfg.mode, cfg.xdp_flags, cfg.ifindex, cfg.ifname,
                cfg.bpf_filepath, cfg.progsec);
  loader.Start();

  system(
      "/usr/bin/bash /home/aino/Projects/xapture/xilter/filter-test/ip.sh "
      "ip_ttl");

  Stats stats("veth1", "filter-test/ip_ttl_min.yaml");
  __u32 key = 1;
  datarec value1 = stats.GetMapValueForTesting(key);
  key++;
  datarec value2 = stats.GetMapValueForTesting(key);
  key++;
  datarec value3 = stats.GetMapValueForTesting(key);
  key++;
  datarec value4 = stats.GetMapValueForTesting(key);
  key++;
  datarec value5 = stats.GetMapValueForTesting(key);
  // fiter1 is ttl>=255.
  // fiter2 is ttl>=64.
  // fiter3 is ttl>=32.
  // fiter4 is ttl>=16.
  // fiter5 is ttl>=1.
  // filter1's value shouldn't be small because if so, any packets will be
  // filterd by the filter1.
  // In this test,
  // send 1 packets of ttl=2.
  // send 2 packets of ttl=20.
  // send 3 packets of ttl=40.
  // send 4 packets of ttl=80.
  // send 5 packets of ttl=240.
  EXPECT_EQ(0, value1.rx_packets);
  EXPECT_EQ(9, value2.rx_packets);
  EXPECT_EQ(3, value3.rx_packets);
  EXPECT_EQ(2, value4.rx_packets);
  EXPECT_EQ(1, value5.rx_packets);

  loader.DetachBpf();
}

TEST(IPTest, FilterByTTLMax) {
  config cfg;
  cfg.mode = Mode::Attach;
  cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
  cfg.ifindex = if_nametoindex("veth1");
  cfg.ifname = "veth1";
  cfg.bpf_filepath = "filter-test/xdp_test_ip_ttl_max.o";
  cfg.progsec = "xdp_generated";
  Loader loader(cfg.mode, cfg.xdp_flags, cfg.ifindex, cfg.ifname,
                cfg.bpf_filepath, cfg.progsec);
  loader.Start();

  system(
      "/usr/bin/bash /home/aino/Projects/xapture/xilter/filter-test/ip.sh "
      "ip_ttl");

  Stats stats("veth1", "filter-test/ip_ttl_max.yaml");
  __u32 key = 1;
  datarec value1 = stats.GetMapValueForTesting(key);
  key++;
  datarec value2 = stats.GetMapValueForTesting(key);
  key++;
  datarec value3 = stats.GetMapValueForTesting(key);
  key++;
  datarec value4 = stats.GetMapValueForTesting(key);
  key++;
  datarec value5 = stats.GetMapValueForTesting(key);
  // fiter1 is ttl<=1.
  // fiter2 is ttl<=16.
  // fiter3 is ttl<=32.
  // fiter4 is ttl<=64.
  // fiter5 is ttl<=255.
  // In this test,
  // send 1 packets of ttl=2.
  // send 2 packets of ttl=20.
  // send 3 packets of ttl=40.
  // send 4 packets of ttl=80.
  // send 5 packets of ttl=240.
  EXPECT_EQ(0, value1.rx_packets);
  EXPECT_EQ(1, value2.rx_packets);
  EXPECT_EQ(2, value3.rx_packets);
  EXPECT_EQ(3, value4.rx_packets);
  EXPECT_EQ(9, value5.rx_packets);

  loader.DetachBpf();
}

TEST(IPTest, FilterByTotLenMin) {
  config cfg;
  cfg.mode = Mode::Attach;
  cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
  cfg.ifindex = if_nametoindex("veth1");
  cfg.ifname = "veth1";
  cfg.bpf_filepath = "filter-test/xdp_test_ip_tot_len_min.o";
  cfg.progsec = "xdp_generated";
  Loader loader(cfg.mode, cfg.xdp_flags, cfg.ifindex, cfg.ifname,
                cfg.bpf_filepath, cfg.progsec);
  loader.Start();

  system(
      "/usr/bin/bash /home/aino/Projects/xapture/xilter/filter-test/ip.sh "
      "ip_tot_len");

  Stats stats("veth1", "filter-test/ip_tot_len_min.yaml");
  __u32 key = 1;
  datarec value1 = stats.GetMapValueForTesting(key);
  key++;
  datarec value2 = stats.GetMapValueForTesting(key);
  key++;
  datarec value3 = stats.GetMapValueForTesting(key);
  key++;
  datarec value4 = stats.GetMapValueForTesting(key);
  key++;
  datarec value5 = stats.GetMapValueForTesting(key);
  // fiter1 is ttl>=1500.
  // fiter2 is ttl>=1024.
  // fiter3 is ttl>=512.
  // fiter4 is ttl>=128.
  // fiter5 is ttl>=64.
  // filter1's value shouldn't be small because if so, any packets will be
  // filterd by the filter1.
  // In this test,
  // send 1 packets of tot_len=48.
  // send 2 packets of tot_len=68.
  // send 3 packets of tot_len=228.
  // send 4 packets of tot_len=528.
  // send 5 packets of tot_len=1028.
  EXPECT_EQ(0, value1.rx_packets);
  EXPECT_EQ(5, value2.rx_packets);
  EXPECT_EQ(4, value3.rx_packets);
  EXPECT_EQ(3, value4.rx_packets);
  EXPECT_EQ(2, value5.rx_packets);

  loader.DetachBpf();
}

TEST(IPTest, FilterByTotLenMax) {
  config cfg;
  cfg.mode = Mode::Attach;
  cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
  cfg.ifindex = if_nametoindex("veth1");
  cfg.ifname = "veth1";
  cfg.bpf_filepath = "filter-test/xdp_test_ip_tot_len_max.o";
  cfg.progsec = "xdp_generated";
  Loader loader(cfg.mode, cfg.xdp_flags, cfg.ifindex, cfg.ifname,
                cfg.bpf_filepath, cfg.progsec);
  loader.Start();

  system(
      "/usr/bin/bash /home/aino/Projects/xapture/xilter/filter-test/ip.sh "
      "ip_tot_len");

  Stats stats("veth1", "filter-test/ip_tot_len_max.yaml");
  __u32 key = 1;
  datarec value1 = stats.GetMapValueForTesting(key);
  key++;
  datarec value2 = stats.GetMapValueForTesting(key);
  key++;
  datarec value3 = stats.GetMapValueForTesting(key);
  key++;
  datarec value4 = stats.GetMapValueForTesting(key);
  key++;
  datarec value5 = stats.GetMapValueForTesting(key);
  // fiter1 is ttl<=64.
  // fiter2 is ttl<=128.
  // fiter3 is ttl<=512.
  // fiter4 is ttl<=1024.
  // fiter5 is ttl<=1500.
  // In this test,
  // send 1 packets of tot_len=48.
  // send 2 packets of tot_len=68.
  // send 3 packets of tot_len=228.
  // send 4 packets of tot_len=528.
  // send 5 packets of tot_len=1028.
  EXPECT_EQ(1, value1.rx_packets);
  EXPECT_EQ(2, value2.rx_packets);
  EXPECT_EQ(3, value3.rx_packets);
  EXPECT_EQ(4, value4.rx_packets);
  EXPECT_EQ(5, value5.rx_packets);

  loader.DetachBpf();
}
