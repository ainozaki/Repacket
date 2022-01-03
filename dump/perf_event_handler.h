#ifndef PERF_EVENT_HANDLER_
#define PERF_EVENT_HANDLER_

#include <bpf/libbpf.h>
#include <linux/perf_event.h>

struct perf_event_mmap_page;

typedef enum bpf_perf_event_ret (*perf_event_print_fn)(void *data, int size);

struct perf_event_sample {
  struct perf_event_header header;
  __u32 size;
  char data[];
};

int perf_event(int *map_fd);

int setup(int *map_fd, int cpu_num);

int mmap_header(int fd, struct perf_event_mmap_page **header);

void poll_perf_event(int *fds, struct perf_event_mmap_page **headers,
                     int num_fds, perf_event_print_fn output_fn, int *done);

int print_bpf_output(void *data, int size);

enum bpf_perf_event_ret
bpf_perf_event_print(struct perf_event_header *hdr, void *private_data);

#endif // PERF_EVENT_HANDLER_
