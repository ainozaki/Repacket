#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "base/define/define.h"
#include "core/loader/loader.h"
#include "core/stats/stats.h"

TEST(TcpTest, FilterBySrc) {
  config cfg;
  cfg.mode = Mode::Attach;
  cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
  cfg.ifindex = if_nametoindex("veth1");
  cfg.ifname = "veth1";
  cfg.bpf_filepath = "filter-test/xdp_test_tcp_src.o";
  cfg.progsec = "xdp_generated";
  Loader loader(cfg.mode, cfg.xdp_flags, cfg.ifindex, cfg.ifname,
                cfg.bpf_filepath, cfg.progsec);
  loader.Start();
  system(
      "/usr/bin/bash /home/vagrant/MocTok/src/filter-test/tcp.sh "
      "tcp_src");

  Stats stats("veth1", "filter-test/tcp_src.yaml");
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

TEST(TcpTest, FilterByDst) {
  config cfg;
  cfg.mode = Mode::Attach;
  cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
  cfg.ifindex = if_nametoindex("veth1");
  cfg.ifname = "veth1";
  cfg.bpf_filepath = "filter-test/xdp_test_tcp_dst.o";
  cfg.progsec = "xdp_generated";
  Loader loader(cfg.mode, cfg.xdp_flags, cfg.ifindex, cfg.ifname,
                cfg.bpf_filepath, cfg.progsec);
  loader.Start();
  system(
      "/usr/bin/bash /home/vagrant/MocTok/src/filter-test/tcp.sh "
      "tcp_dst");

  Stats stats("veth1", "filter-test/tcp_dst.yaml");
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

TEST(TcpTest, FilterByFlags) {
  config cfg;
  cfg.mode = Mode::Attach;
  cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
  cfg.ifindex = if_nametoindex("veth1");
  cfg.ifname = "veth1";
  cfg.bpf_filepath = "filter-test/xdp_test_tcp_flags.o";
  cfg.progsec = "xdp_generated";
  Loader loader(cfg.mode, cfg.xdp_flags, cfg.ifindex, cfg.ifname,
                cfg.bpf_filepath, cfg.progsec);
  loader.Start();
  system(
      "/usr/bin/bash /home/vagrant/MocTok/src/filter-test/tcp.sh "
      "tcp_flags");

  Stats stats("veth1", "filter-test/tcp_flags.yaml");
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
  key++;
  datarec value6 = stats.GetMapValueForTesting(key);
  EXPECT_EQ(2, value1.rx_packets);
  EXPECT_EQ(2, value2.rx_packets);
  EXPECT_EQ(2, value3.rx_packets);
  EXPECT_EQ(2, value4.rx_packets);
  EXPECT_EQ(2, value5.rx_packets);
  EXPECT_EQ(2, value6.rx_packets);

  loader.DetachBpf();
}
