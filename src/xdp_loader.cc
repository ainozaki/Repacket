#include <iostream>
#include <string>

#include <stdio.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <net/if.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "cmdline.h"
#include "common/common_kern_user.h"
#include "define.h"

struct record {
    __u64 timestamp;
    struct datarec total;
};

struct stats_record {
    struct record stats[2];
};

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd) {
    int err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
    if (err) {
        std::cout << "ERR: attach xdp object to net_device" << std::endl;
        return err;
    }
    std::cout << "Success: attach XDP pbject." << std::endl;
    return EXIT_OK;
}

struct bpf_object* load_bpf_and_attach_xdp(const struct config& cfg) {
    int prog_fd = -1;
    struct bpf_object* bpf_obj;
    struct bpf_program* bpf_prog;

    // Load the BPF-ELF file.
    int err =
        bpf_prog_load(cfg.filename, BPF_PROG_TYPE_XDP, &bpf_obj, &prog_fd);
    if (err) {
        std::cout << "ERR: loading BPF-OBJ file." << std::endl;
        exit(EXIT_FAIL_BPF);
    }

    // Find the selected prog section.
    bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg.progsec.c_str());
    if (!bpf_prog) {
        std::cout << "ERR: finding prog sec: " << cfg.progsec << std::endl;
        exit(EXIT_FAIL_BPF);
    }

    // Find the correspond FD.
    prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd <= 0) {
        std::cout << "ERR: bpf_program__fd" << std::endl;
        exit(EXIT_FAIL_BPF);
    }

    // Attach the FD to the interface `cfg.ifname`.
    err = xdp_link_attach(cfg.ifindex, cfg.xdp_flags, prog_fd);
    if (err) {
        std::cout << "ERR: attaching XDP." << std::endl;
        exit(EXIT_FAIL_BPF);
    }

    std::cout << "Success: loading BPF and attach XDP." << std::endl;
    return bpf_obj;
}

int xdp_link_detach(int ifindex, __u32 xdp_flags) {
    int err;
    if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
        std::cout << "ERR: detach xdp object failed." << std::endl;
        return EXIT_FAIL_XDP;
    }
    std::cout << "Success: detach XDP pbject." << std::endl;
    return EXIT_OK;
}

int find_map_fd(struct bpf_object* bpf_obj, const char* mapname) {
    // Find the map object by name.
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj, mapname);
    if (!map) {
        std::cout << "ERR: find map failed." << std::endl;
        return -1;
    }

    // Find the correspond FD.
    int map_fd = bpf_map__fd(map);
    return map_fd;
}

int check_map_fd_info(int map_fd,
                      struct bpf_map_info* info,
                      struct bpf_map_info* exp) {
    __u32 info_len = sizeof(*info);
    int err;

    if (map_fd < 0)
        return EXIT_FAIL;

    // BPF-info via bpf-syscall
    err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
    if (err) {
        std::cout << "ERR: Cannot get info." << std::endl;
        return EXIT_FAIL_BPF;
    }
    if (exp->key_size && exp->key_size != info->key_size) {
        std::cout << "ERR: Unexpected size." << std::endl;
        return EXIT_FAIL;
    }
    if (exp->value_size && exp->value_size != info->value_size) {
        std::cout << "ERR: Unexpected value size." << std::endl;
        return EXIT_FAIL;
    }
    if (exp->max_entries && exp->max_entries != info->max_entries) {
        std::cout << "ERR: Unexpected max_entries value." << std::endl;
        return EXIT_FAIL;
    }
    if (exp->type && exp->type != info->type) {
        std::cout << "ERR: Unexpected type." << std::endl;
        return EXIT_FAIL;
    }
    return 0;
}

__u64 gettime() {
    struct timespec t;
    int res;

    res = clock_gettime(CLOCK_MONOTONIC, &t);
    if (res < 0) {
        std::cout << "ERR: gettime. " << std::endl;
        exit(EXIT_FAIL);
    }
    return (__u64)t.tv_sec * 1000000000 + t.tv_nsec;
}

void map_get_value_array(int fd, __u32 key, struct datarec* value) {
    if ((bpf_map_lookup_elem(fd, &key, value)) != 0) {
        std::cout << "ERR: bpf_map_lookup_elem" << std::endl;
    }
}

bool map_collect(int fd, __u32 map_type, __u32 key, struct record* rec) {
    struct datarec value;
    rec->timestamp = gettime();
    switch (map_type) {
        case BPF_MAP_TYPE_ARRAY:
            map_get_value_array(fd, key, &value);
            break;
        default:
            std::cout << "Unknown map type." << std::endl;
            return false;
            break;
    }
    rec->total.rx_packets = value.rx_packets;
    rec->total.rx_bytes = value.rx_bytes;
    return true;
}

void stats_collect(int map_fd, __u32 map_type, struct stats_record* stats_rec) {
    __u32 key_pass = XDP_PASS;
    __u32 key_drop = XDP_DROP;

    map_collect(map_fd, map_type, key_pass, &stats_rec->stats[0]);
    map_collect(map_fd, map_type, key_drop, &stats_rec->stats[1]);
}

double calc_period(struct record* rec, struct record* prev) {
    double period_ = 0;
    __u64 period = 0;
    period = rec->timestamp - prev->timestamp;
    if (period > 0) {
        period_ = ((double)period / 1000000000);
    }
    return period_;
}

void stats_print(struct stats_record* stats_rec,
                 struct stats_record* stats_prev) {
    struct record *rec, *prev;
    double period;
    __u64 packets, bytes;
    double pps, bps;

    printf(
        "----------------------------------------------------------------------"
        "-------------------------------------\n");
    for (int i = 0; i < 2; i++) {
        const char* fmt =
            "%-12s %'11lld pkts (%'10.0f pps)"
            " %'11lld bytes (%'6.0f bytes/s)"
            " period:%f\n";

        const char* action;
        switch (i) {
            case 0:
                action = "XDP_PASS";
                break;
            case 1:
                action = "XDP_DROP";
                break;
        }
        rec = &stats_rec->stats[i];
        prev = &stats_prev->stats[i];

        period = calc_period(rec, prev);
        if (period == 0)
            return;

        packets = rec->total.rx_packets - prev->total.rx_packets;
        pps = packets / period;

        bytes = rec->total.rx_bytes - prev->total.rx_bytes;
        bps = bytes / period;

        printf(fmt, action, rec->total.rx_packets, pps, rec->total.rx_bytes,
               bps, period);
    }
}

void stats_poll(int map_fd, __u32 map_type) {
    struct stats_record prev, record = {0};

    // Initial reading
    stats_collect(map_fd, map_type, &record);
    usleep(1000000 / 4);

    while (1) {
        prev = record;
        stats_collect(map_fd, map_type, &record);
        stats_print(&record, &prev);
        sleep(1);
    }
}

int main(int argc, char** argv) {
    char kFilename[] = "xdpidms.o";
    char kIfname[] = "veth1";
    char progsec[] = "xdp_drop";
    int err;

    // Make a rule of cmdline parser.
    cmdline::parser parser;
    parser.add("unload", 'u', "Unload XDP object from veth1.");
    parser.add<std::string>("sec", 's', "Specify the program SEC to load.",
                            false, "xdp_drop");
    parser.parse(argc, argv);

    struct config cfg = {
        .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
        .ifindex = if_nametoindex(kIfname),
        .ifname = kIfname,
        .filename = kFilename,
        .progsec = progsec,
    };

    // Detach XDP object from veth1.
    if (parser.exist("unload")) {
        err = xdp_link_detach(cfg.ifindex, cfg.xdp_flags);
        if (err) {
            std::cout << "ERR: unload xdp object" << std::endl;
            return EXIT_FAIL_XDP;
        }
        std::cout << "Success: unload xdp object" << std::endl;
        return EXIT_OK;
    }

    // Specify progsec to load.
    if (parser.exist("sec")) {
        cfg.progsec = parser.get<std::string>("sec");
    }

    // Load the BPF-ELF object file and attach XDP to interface.
    struct bpf_object* bpf_obj = load_bpf_and_attach_xdp(cfg);
    if (!bpf_obj) {
        std::cout << "ERR: loading the BPF file and attach XDP to interface."
                  << std::endl;
        return EXIT_FAIL_BPF;
    }

    std::cout << "Success: Loading XDP prog: " << kFilename;
    std::cout << ", on device: " << cfg.ifname;
    std::cout << ", progsec: " << cfg.progsec << std::endl;

    // Locate the map FD.
    int stats_map_fd = find_map_fd(bpf_obj, "xdp_stats_map");
    if (stats_map_fd < 0) {
        std::cout << "ERR: find map fd." << std::endl;
        std::cout << "Detach BPF object." << std::endl;
        xdp_link_detach(cfg.ifindex, cfg.xdp_flags);
        return EXIT_FAIL_BPF;
    }

    // Check map info.
    struct bpf_map_info map_expect = {0};
    struct bpf_map_info info = {0};
    map_expect.key_size = sizeof(__u32);
    map_expect.value_size = sizeof(struct datarec);
    map_expect.max_entries = 5;
    err = check_map_fd_info(stats_map_fd, &info, &map_expect);
    if (err) {
        std::cout << "ERR: Unexpected map info." << std::endl;
        return err;
    }
    std::cout << "Correcting stats from BPF map..." << std::endl;
    printf(
        " - BPF map (bpf_map_type:%d) id:%d name:%s"
        " key_size:%d value_size:%d max_entries:%d\n",
        info.type, info.id, info.name, info.key_size, info.value_size,
        info.max_entries);
    stats_poll(stats_map_fd, info.type);

    std::cout << "All succeed." << std::endl;
    return EXIT_OK;
}
