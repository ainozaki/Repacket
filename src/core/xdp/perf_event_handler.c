#include "perf_event_handler.h"

#include <bpf/bpf.h>

#include <assert.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "base/config.h"
#include "base/logger.h"
#include "core/dump/print.h"
#include "core/xdp/loader.h"

#define MAX_CPUS 128
#define PAGE_CNT 8

static int pmu_fds[MAX_CPUS];
static struct perf_event_mmap_page* headers[MAX_CPUS];
static int done;

static struct config* config;

static int packet_captured = 0;
static int catch_signal = 0;

int perf_event(struct config* cfg, int* map_fd) {
  int err;
  int cpu_num = libbpf_num_possible_cpus();

  config = cfg;

  // Setup for perf events.
  err = setup_perf(map_fd, cpu_num);
  if (err) {
    LOG_ERROR("Err: Cannot setup for perf event\n");
    return err;
  }

  // Run poll and handle events enqued.
  poll_perf_event(pmu_fds, headers, cpu_num, print_dump, &done);
  return 0;
}

int setup_perf(int* map_fd, int cpu_num) {
  // |map_fd| is set at loader.
  assert(*map_fd > 0);

  struct perf_event_attr attr = {
      .sample_type = PERF_SAMPLE_RAW,
      .type = PERF_TYPE_SOFTWARE,
      .config = PERF_COUNT_SW_BPF_OUTPUT,
      .wakeup_events = 1,
  };

  for (int i = 0; i < cpu_num; i++) {
    int key = i;
    pmu_fds[i] = syscall(SYS_perf_event_open, &attr, /*pid=*/-1, /*cpu=*/i,
                         /*group_fd*/ -1, 0);
    assert(pmu_fds[i] >= 0);
    bpf_map_update_elem(*map_fd, &key, &pmu_fds[i], BPF_ANY);
    ioctl(pmu_fds[i], PERF_EVENT_IOC_ENABLE, 0);
  }

  for (int i = 0; i < cpu_num; i++) {
    int err = mmap_header(pmu_fds[i], &headers[i]);
    if (err) {
      LOG_ERROR("Err: Cannot mmap headers.\n");
      return err;
    }
  }
  LOG_INFO("Success: setup for perf event,\n");
  return 0;
}

int mmap_header(int fd, struct perf_event_mmap_page** header) {
  void* base;

  int page_size = getpagesize();
  int mmap_size = page_size * (PAGE_CNT + 1);

  base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (base == MAP_FAILED) {
    LOG_ERROR("Error while mmap().\n");
    return -1;
  }
  *header = base;
  return 0;
}

void poll_perf_event(int* fds,
                     struct perf_event_mmap_page** headers,
                     int num_fds,
                     perf_event_print_fn output_fn,
                     int* done) {
  struct pollfd* pfds;
  void* buf = NULL;
  size_t len = 0;
  int cpu_num = libbpf_num_possible_cpus();
  int page_size = getpagesize();

  // register SIGNINT handler.
  struct sigaction sa;
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = signal_handler;
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, NULL);

  pfds = calloc(cpu_num, sizeof(*pfds));
  if (!pfds) {
    LOG_ERROR("ERR: Cannot calloc.\n");
    return;
  }

  for (int i = 0; i < cpu_num; i++) {
    pfds[i].fd = pmu_fds[i];
    pfds[i].events = POLLIN;
  }

  LOG_INFO("Waiting for packets...\n");

  // SIGNINT makes |catch_signal| true.
  while (!catch_signal) {
    poll(pfds, cpu_num, 1000);
    for (int i = 0; i < cpu_num; i++) {
      if (!pfds[i].revents) {
        continue;
      }
      int ret = bpf_perf_event_read_simple(headers[i], PAGE_CNT * page_size,
                                           page_size, &buf, &len,
                                           bpf_perf_event_print, output_fn);
    }
  }
  free(buf);
  free(pfds);
  cleanup();
}

enum bpf_perf_event_ret bpf_perf_event_print(struct perf_event_header* hdr,
                                             void* private_data) {
  struct perf_event_sample* e = (struct perf_event_sample*)hdr;
  perf_event_print_fn fn = private_data;
  int ret;

  packet_captured++;

  if (e->header.type == PERF_RECORD_SAMPLE) {
    ret = fn(e->data, e->size);
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

int print_dump(void* data, int size) {
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

  // TODO: convert or make pkt_len to __u8.
  start_dump(e->pkt_data, e->pkt_len);

  return LIBBPF_PERF_EVENT_CONT;
}

void signal_handler() {
  catch_signal = 1;
}

void cleanup() {
  printf("\n%d packets captured.\n", packet_captured);
  int err = detach(config);
  if (err) {
    LOG_ERROR("Failed to detach XDP from %s\n", config->ifname);
  }
}
