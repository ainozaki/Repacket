#include <iostream>
#include <string>

#include <stdio.h>

#include <linux/if_link.h>
#include <net/if.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "cmdline.h"
#include "define.h"

int load_bpf_object_file(const char* filename) {
    int first_prog_fd = -1;
    struct bpf_object* obj;

    // Use libbpf for loading BPF object file.
    int err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &first_prog_fd);
    if (err) {
        std::cout << "ERR: loading BPF-OBJ file." << std::endl;
        std::cout << "prog_fd is: " << first_prog_fd << std::endl;
        return EXIT_FAIL;
    }
    std::cout << "Success: loading BPF-OBJ file." << std::endl;
    std::cout << "prog_fd is: " << first_prog_fd << std::endl;
    return first_prog_fd;
}

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd) {
    int err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
    if (err) {
        std::cout << "ERR: attach xdp object to net_device" << std::endl;
        return err;
    }
    std::cout << "Success: attach XDP pbject." << std::endl;
    return EXIT_OK;
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

int main(int argc, char** argv) {
    const char kFilename[] = "xdpidms.o";
    std::string ifname = "veth1";

    /* Make a rule of cmdline parser. */
    cmdline::parser parser;
    parser.add("unload", 'u', "Unload XDP object from veth1.");
    parser.parse(argc, argv);

    struct config cfg = {
        .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
        .ifindex = if_nametoindex(ifname.c_str()),
        .ifname = ifname,
    };

    /* Detach XDP object from veth1. */
    if (parser.exist("unload")) {
        int err = xdp_link_detach(cfg.ifindex, cfg.xdp_flags);
        if (err) {
            std::cout << "ERR: unload xdp object" << std::endl;
            return EXIT_FAIL_XDP;
        }
        std::cout << "Success: unload xdp object" << std::endl;
        return EXIT_OK;
    }

    /* Load the BPF-ELF object file. */
    int prog_fd = load_bpf_object_file(kFilename);
    if (prog_fd <= 0) {
        std::cout << "ERR: loading file: " << kFilename << std::endl;
        return EXIT_FAIL_BPF;
    }

    /* Attach the FD to net_device. */
    int err = xdp_link_attach(cfg.ifindex, cfg.xdp_flags, prog_fd);
    if (err) {
        std::cout << "ERR: attaching file: " << kFilename << std::endl;
        return EXIT_FAIL_XDP;
    }

    std::cout << "Success: Loading XDP prog: " << kFilename;
    std::cout << " on device: " << cfg.ifname << std::endl;

    return EXIT_OK;
}
