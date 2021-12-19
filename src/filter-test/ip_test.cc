#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "base/define/define.h"
#include "core/loader/loader.h"
#include "core/stats/stats.h"

TEST(IPTest, DropByProtocol) {
  config cfg;
  cfg.mode = Mode::Attach;
  cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
  cfg.ifindex = if_nametoindex("veth1");
  cfg.ifname = "veth1";
  cfg.bpf_filepath = "filter-test/xdp_test_ip_protocol.o";
  cfg.progsec = "xdp_generated";
  Loader loader(cfg.mode, cfg.xdp_flags, cfg.ifindex, cfg.ifname,
                cfg.bpf_filepath, cfg.progsec);

  system(
      "/usr/bin/bash /home/vagrant/MocTok/src/filter-test/ip_test.sh "
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
