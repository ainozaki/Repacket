#include "core/xdp/perf_handler.h"

#include <iostream>

extern "C" {
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
}

#include "base/config.h"
#include "base/logger.h"
#include "core/dump/print.h"
#include "core/xdp/loader.h"

#define MAX_CPUS 12
#define PAGE_CNT 8

bool catch_signal = false;
int packet_captured = 0;
struct config config;

namespace {

void SignalHandler(int signum) {
  catch_signal = true;
}

int PrintDump(void* data, int size) {
  struct packed {
    __u16 cookie;
    __u16 pkt_len;
    __u8 pkt_data[1024];
  };
  struct packed* e = (struct packed*)data;

  struct timespec ts;
  int err;

  if (e->cookie != 0xdead) {
    printf("BUG cookie %x sized %d\n", e->cookie, size);
    return LIBBPF_PERF_EVENT_ERROR;
  }

  err = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (err < 0) {
    LOG_ERROR("Error with clock_gettime! (%i)\n", err);
    return LIBBPF_PERF_EVENT_ERROR;
  }

  StartDump(config, e->pkt_data, e->pkt_len);
  return 0;
}

enum bpf_perf_event_ret PerfEventRecord(struct perf_event_header* hdr,
                                        void* private_data) {
  struct perf_event_sample* e = (struct perf_event_sample*)hdr;
  int ret;
  packet_captured++;

  if (e->header.type == PERF_RECORD_SAMPLE) {
    ret = PrintDump(e->data, e->size);
  } else if (e->header.type == PERF_RECORD_LOST) {
    struct Lost {
      struct perf_event_header header;
      __u64 id;
      __u64 lost;
    };
    struct Lost* lost = (struct Lost*)e;
    printf("lost %lld events\n", lost->lost);
  } else {
    printf("unknown event type=%d size=%d\n", e->header.type, e->header.size);
  }

  return LIBBPF_PERF_EVENT_CONT;
}

}  // namespace

PerfHandler::PerfHandler(const struct config& cfg, int map_fd)
    : map_fd_(map_fd) {
  config = cfg;
  cpu_num_ = get_nprocs();
}

int PerfHandler::Start() {
  int err;

  // Setup for perf events.
  if (SetupPerf()) {
    LOG_ERROR("Err: Cannot setup for perf event\n");
    return err;
  }

  // Run poll and handle events enqued.
  PollPerfEvent();
  return 0;
}

int PerfHandler::SetupPerf() {
  // |map_fd_| is set at loader.
  assert(map_fd_ > 0);

  struct perf_event_attr attr = {0};
  attr.sample_type = PERF_SAMPLE_RAW;
  attr.type = PERF_TYPE_SOFTWARE;
  attr.config = PERF_COUNT_SW_BPF_OUTPUT;
  attr.wakeup_events = 1;

  int key;
  LOG_DEBUG("cpu_num_ : %d\n", cpu_num_);
  for (int i = 0; i < cpu_num_; i++) {
    key = i;
    int fd = syscall(SYS_perf_event_open, &attr, /*pid=*/-1, /*cpu=*/i,
                     /*group_fd*/ -1, 0);
    pmu_fds_[i] = fd;
    if (pmu_fds_[i] < 0) {
      // If extra byte of struct perf_event_attr isn't zero, it fails. (errno =
      // 7)
      LOG_ERROR("perf event open failed. pmu_fds_[%d] = %d, errno: %d\n", i,
                pmu_fds_[i], errno);
      Cleanup();
    }
    bpf_map_update_elem(map_fd_, &key, &pmu_fds_[i], BPF_ANY);
    ioctl(pmu_fds_[i], PERF_EVENT_IOC_ENABLE, 0);
  }

  for (int i = 0; i < cpu_num_; i++) {
    if (MmapHeader(pmu_fds_[i], &headers_[i])) {
      LOG_ERROR("Err: Cannot mmap headers.\n");
      return 1;
    }
  }
  LOG_INFO("Success: setup for perf event,\n");
  return 0;
}

int PerfHandler::MmapHeader(int fd, struct perf_event_mmap_page** header) {
  void* base;

  int page_size = getpagesize();
  int mmap_size = page_size * (PAGE_CNT + 1);

  base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (base == MAP_FAILED) {
    LOG_ERROR("Error while mmap().\n");
    return -1;
  }
  *header = (struct perf_event_mmap_page*)base;
  return 0;
}

void PerfHandler::PollPerfEvent() {
  struct pollfd* pfds;
  void* buf = NULL;
  void* private_data = NULL;
  size_t len = 0;
  int page_size = getpagesize();

  // register SIGNINT handler.
  struct sigaction sa;
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = SignalHandler;
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, NULL);

  pfds = (pollfd*)calloc(cpu_num_, sizeof(*pfds));
  if (!pfds) {
    LOG_ERROR("ERR: Cannot calloc.\n");
    return;
  }

  for (int i = 0; i < cpu_num_; i++) {
    pfds[i].fd = pmu_fds_[i];
    pfds[i].events = POLLIN;
  }

  LOG_INFO("Waiting for packets...\n");

  // SIGNINT makes |catch_signal_| true.
  // perf_event_print_fn *output_fn = (perf_event_print_fn *)&PrintDump;
  while (!catch_signal) {
    poll(pfds, cpu_num_, 1000);
    for (int i = 0; i < cpu_num_; i++) {
      if (!pfds[i].revents) {
        continue;
      }
      int ret = bpf_perf_event_read_simple(headers_[i], PAGE_CNT * page_size,
                                           page_size, &buf, &len,
                                           PerfEventRecord, private_data);
    }
  }
  free(buf);
  free(pfds);
  Cleanup();
}

void SignalHandler() {
  catch_signal = true;
}

void PerfHandler::Cleanup() {
  std::cout << "\n" << packet_captured << " packets captured." << std::endl;
  Loader loader(config);
  int err = loader.Detach();
  if (err) {
    LOG_ERROR("Failed to detach XDP from %s\n", config.ifname.c_str());
  }
  exit(1);
}
