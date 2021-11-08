#include <iostream>
#include <stdio.h>

#include "../libbpf/src/bpf.h"
#include "../libbpf/src/libbpf.h"

int load_bpf_object_file(const char *filename){
	int first_prog_fd = -1;
	struct bpf_object *obj;

	// Use libbpf for loading BPF object file.
	int err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &first_prog_fd);
	if (err) {
		std::cout << "ERR: loading BPF-OBJ file." << std::endl;
		std::cout << "prog_fd is: " << first_prog_fd << std::endl;
		return -1;
	}
	
	std::cout << "Success: loading BPF-OBJ file." << std::endl;
	std::cout << "prog_fd is: " << first_prog_fd << std::endl;
	return first_prog_fd;
}

int main(){
	const char kFilename[] = "xdpidms.o";

	/* Load the BPF-ELF object file and get back first BPF_prog FD */
	int prog_fd = load_bpf_object_file(kFilename);
	if (prog_fd <= 0) {
		std::cout <<  "ERR: loading file: " << kFilename << std::endl;
		return -1;
	}

	return 1;
}
