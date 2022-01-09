#include "core/dump/print.h"

#include <stdio.h>

#include "core/dump/def/icmp.h"

void icmp_print(const unsigned char* p, uint8_t len) {
	uint8_t icmp_type;
	struct icmp *icmp;

	icmp = (struct icmp *)p; 
	icmp_type = *(icmp->type);
	
	printf("ICMP ");
	switch (icmp_type){
		case ICMP_ECHO_REPLY:
			printf("echo reply, ");
			break;
		case ICMP_UNREACHABLE:
			printf("unreachable, ");
			break;
		case ICMP_REDIRECT:
			printf("redirect, ");
			break;
		case ICMP_ECHO_REQUEST:
			printf("echo request, ");
			break;
		case ICMP_TIME_EXCEEDED:
			printf("time exceeded, ");
			break;
		default:
			printf("unknown type, ");
	}
	printf("len %d", len);
}
