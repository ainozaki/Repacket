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
      "/usr/bin/bash /home/vagrant/MocTok/src/filter-test/ip.sh "
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
      "/usr/bin/bash /home/vagrant/MocTok/src/filter-test/ip.sh "
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
