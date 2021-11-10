#include <iostream>
#include <string>

#include <stdio.h>

#include <linux/if_link.h>
#include <net/if.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "cmdline.h"
#include "define.h"

int load_bpf_object_file(const struct config& cfg) {
    int prog_fd = -1;
    struct bpf_object* bpf_obj;
    struct bpf_program* bpf_prog;

    // Load the BPF-ELF file.
    int err = bpf_prog_load(cfg.filename, BPF_PROG_TYPE_XDP, &bpf_obj, &prog_fd);
    if (err) {
        std::cout << "ERR: loading BPF-OBJ file." << std::endl;
        return EXIT_FAIL_BPF;
    }

    // Find the selected prog section.
    bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg.progsec.c_str());
    if (!bpf_prog){
        std::cout << "ERR: finding prog sec: " << cfg.progsec << std::endl;
        return EXIT_FAIL_BPF;
    }

    prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd <= 0){
        std::cout << "ERR: bpf_program__fd" << std::endl;
        return EXIT_FAIL_BPF;
    }

    std::cout << "Success: loading BPF-OBJ file." << std::endl;
    std::cout << "prog_fd is: " << prog_fd << std::endl;
    return prog_fd;
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
    char kFilename[] = "xdpidms.o";
    char kIfname[] = "veth1";
    char progsec[] = "xdp_drop";

    /* Make a rule of cmdline parser. */
    cmdline::parser parser;
    parser.add("unload", 'u', "Unload XDP object from veth1.");
    parser.add<std::string>("sec", 's', "Specify the program SEC to load.", false, "xdp_drop");
    parser.parse(argc, argv);

    struct config cfg = {
        .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
        .ifindex = if_nametoindex(kIfname),
        .ifname = kIfname,
        .filename = kFilename,
        .progsec = progsec,
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

    /* Specify progsec to load. */
    if (parser.exist("sec")){
        cfg.progsec = parser.get<std::string>("sec");
    }

    /* Load the BPF-ELF object file. */
    int prog_fd = load_bpf_object_file(cfg);
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
    std::cout << ", on device: " << cfg.ifname;
    std::cout << ", progsec: " << cfg.progsec << std::endl;

    return EXIT_OK;
}
