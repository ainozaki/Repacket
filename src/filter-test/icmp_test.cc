#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "base/define/define.h"
#include "core/loader/loader.h"
#include "core/stats/stats.h"

TEST(IcmpTest, PassByType) {
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

  system("/usr/bin/bash /home/vagrant/MocTok/src/filter-test/icmp.sh");

  Stats stats("veth1");
  __u32 key = 0;
  datarec value0 = stats.GetMapValueForTesting(key);
  EXPECT_EQ(0, value0.rx_packets);
  key++;
  datarec value1 = stats.GetMapValueForTesting(key);
  EXPECT_EQ(0, value1.rx_packets);
  key++;
  datarec value2 = stats.GetMapValueForTesting(key);
  EXPECT_EQ(10, value2.rx_packets);

  loader.DetachBpf();
}
