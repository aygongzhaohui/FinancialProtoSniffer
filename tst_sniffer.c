#include "sniffer.h"
#include <stdio.h>
#include <unistd.h>

int count = 0;

void dump_handler(sniffer * p, char * buf, unsigned len) {
	int i = 0, l = len;
	char * ptr = buf;
	eth_header_t ethh;
	ip_header_t iph;
	tcp_header_t tcph;
	printf("--------------------get a packet from %s, length is %u:\n", p->ifname, len);
	// Ethernet
	parse_eth_header((eth_header *)ptr, &ethh);
	printf("++++Ethernet header info\n");
	printf("%s", str_eth_header(&ethh));
	ptr += ETH_HEAD_LEN;
	l -= ETH_HEAD_LEN;
	if (ethh.type_len == ETH_T_IP) {
		// IP
		parse_ip_header((ip_header *)ptr, &iph);
		printf("++++IP header info\n");
		printf("%s", str_ip_header(&iph));
		ptr += iph.hlen * 4;
		l = iph.length - iph.hlen * 4;
		// TCP
		if (iph.protocol == IPPROTO_TCP) {
			parse_tcp_header((tcp_header *)ptr, &tcph);
			printf("++++TCP header info\n");
			printf("%s", str_tcp_header(&tcph));
			ptr += tcph.hlen;
			l -= tcph.hlen;
		}
	}
	/*
	// data
	l = len;
	printf("    -----------Data----------\n    -");;
	for (; i < l; ++i) {
		printf("%02x ", (unsigned char)buf[i]);
		if ((i + 1) % 16 == 0 && (i + 1) < l)
			printf("\n    -");
	}
	printf("\n");
	printf("    -------------------------\n\n\n");;
	*/
	count++;
	//if (count == 2) stop_sniff(p);
	fflush(stdout);
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

