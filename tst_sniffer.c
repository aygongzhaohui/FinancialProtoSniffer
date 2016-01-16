#include "sniffer.h"
#include <stdio.h>
#include <unistd.h>

void dump_handler(sniffer * p, char * buf, unsigned len) {
	int i = 0;
	printf("get a packet from %s, length is %u\n", p->ifname, len);
	for (; i < len; ++i) {
		printf("%02x ", (unsigned char)buf[i]);
		if ((i + 1) % 16 == 0 && (i + 1) < len) printf("\n");
	}
	printf("\n");
	sleep(1);
}

int main(int argc, char **argv) {
	if (argc < 2) {
		printf("<Usage> tst_sniffer ifname\n");
		return 0;
	}
	sniffer snfr;
	if (init_sniffer(&snfr, 0, 0, argv[1], dump_handler) < 0)
		return -1;
	if (sniffer_open(&snfr) < 0)
		return -1;

	return start_sniff(&snfr);
}
