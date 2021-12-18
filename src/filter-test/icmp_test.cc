#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "base/define/define.h"
#include "core/loader/loader.h"
#include "core/stats/stats.h"

TEST(IcmpTest, DropByType) {
  config cfg;
  cfg.mode = Mode::Attach;
  cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
  cfg.ifindex = if_nametoindex("veth1");
  cfg.ifname = "veth1";
  cfg.bpf_filepath = "filter-test/xdp-generated.o";
  cfg.progsec = "xdp_generated";
  Loader loader(cfg.mode, cfg.xdp_flags, cfg.ifindex, cfg.ifname,
                cfg.bpf_filepath, cfg.progsec);
  std::cout << "loading succeed" << std::endl;

  system("/usr/bin/bash /home/vagrant/MocTok/src/filter-test/icmp_type.sh");

  Stats stats("veth1");
  __u32 key = 0;
  datarec value0 = stats.GetMapValueForTesting(key);
  key++;
  datarec value1 = stats.GetMapValueForTesting(key);
  key++;
  datarec value2 = stats.GetMapValueForTesting(key);
  key++;
  datarec value3 = stats.GetMapValueForTesting(key);
  key++;
  datarec value4 = stats.GetMapValueForTesting(key);
  EXPECT_EQ(3, value0.rx_packets);
  EXPECT_EQ(3, value1.rx_packets);
  EXPECT_EQ(3, value2.rx_packets);
  EXPECT_EQ(3, value3.rx_packets);
  EXPECT_EQ(3, value4.rx_packets);

  loader.DetachBpf();
}
