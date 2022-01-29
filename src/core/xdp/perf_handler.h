#ifndef PERF_EVENT_HANDLER_
#define PERF_EVENT_HANDLER_

extern "C" {
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
}

#include "base/config.h"

#define MAX_CPUS 12
#define PAGE_CNT 8

struct perf_event_mmap_page;

typedef enum bpf_perf_event_ret (*perf_event_print_fn)(void* data, int size);

struct perf_event_sample {
  struct perf_event_header header;
  __u32 size;
  char data[];
};

class PerfHandler {
 public:
  PerfHandler(const struct config& cfg, int map_fd);
  ~PerfHandler() = default;
  PerfHandler(const PerfHandler&) = default;

  // Interface function to start perf event.
  int Start();

 private:
  // Setup.
  int SetupPerf();

  // mmap() memory for the perf event fd.
  int MmapHeader(int fd, struct perf_event_mmap_page** header);

  // Called after SIGINT.
  void Cleanup();

  // Run poll.
  void PollPerfEvent();

  int map_fd_;

  int cpu_num_;

  int packet_captured_ = 0;

  int pmu_fds_[MAX_CPUS];

  struct perf_event_mmap_page* headers_[MAX_CPUS];
};

#endif  // PERF_EVENT_HANDLER_
