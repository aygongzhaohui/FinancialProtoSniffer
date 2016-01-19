/**
 * @file tcpipproto.c
 * @brief	
 * @author GongZhaohui
 * @version 
 * @date 2016-01-16
 */

#include "tcpipproto.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

int parse_eth_header(const eth_header * in, eth_header_t * out) {
	if (!in || !out) return -1;
	memcpy(out->src_mac, in->src_mac, MAC_SIZE);
	memcpy(out->dest_mac, in->dest_mac, MAC_SIZE);
	out->type_len = ntohs(in->type_len);
	return 0;
}

int pack_eth_header(const eth_header_t * in, eth_header * out) {
	if (!in || !out) return -1;
	memcpy(out->src_mac, in->src_mac, MAC_SIZE);
	memcpy(out->dest_mac, in->dest_mac, MAC_SIZE);
	out->type_len = htons(in->type_len);
	return 0;
}

static const char * eth_get_type(unsigned short v) {
	switch (v) {
	case 0x0800:
		return "TCP";
	case 0x0806:
		return "ARP request";
	case 0x8035:
		return "ARP reply";
	default:
		return "unknow type";
	}
}

const char * str_eth_header(const eth_header_t * in) {
	char * ptr;
	static char buf[1024];
	int n = 0, l = sizeof(buf) - 1;
	if (!in) return "";
	ptr = buf;
	n = snprintf(ptr, l, "    Source mac addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
			in->src_mac[0], in->src_mac[1], in->src_mac[2], in->src_mac[3], in->src_mac[4], in->src_mac[5]);
    l -= n;
	ptr += n;
	n = snprintf(ptr, l, "    Destination mac addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
			in->dest_mac[0], in->dest_mac[1], in->dest_mac[2], in->dest_mac[3], in->dest_mac[4], in->dest_mac[5]);
    l -= n;
	ptr += n;
	if (in->type_len > 1500)
		n = snprintf(ptr, l, "    Type: %s(0x%04x)\n", eth_get_type(in->type_len), in->type_len);
	else
		n = snprintf(ptr, l, "    Length: %u\n", in->type_len);
	return buf;
}

int parse_ip_header(const ip_header * in, ip_header_t * out) {
	struct in_addr addr;
	if (!in || !out) return -1;
	memset(out, 0, sizeof(ip_header_t));
	out->version = in->version;
	out->hlen = in->hlen;
	out->tos_pri = in->tos_pri;
	if (in->tos_type == 0)
		out->tos_type = TOS_NONE;
	else if (in->tos_type & 8)
		out->tos_type = MIN_DELAY;
	else if (in->tos_type & 4)
		out->tos_type = MAX_THROUGHPUT;
	else if (in->tos_type & 2)
		out->tos_type = MAX_USABILITY;
	else if (in->tos_type & 1)
		out->tos_type = MIN_COST;
	else {
		printf("parse_ip_header- unkown tos type %u\n", in->tos_type);
		return -1;
	}
	out->length = ntohs(in->length);
	out->id = ntohs(in->id);
	out->offset = ntohs(in->offset);
	if (out->offset & 0x4000) {
		out->frag = DONT_FRAG;
		out->offset = 0;
	} else {
		if (out->offset & 0x2000)
			out->frag = MORE_FRAG;
		else
			out->frag = END_FRAG;
		out->offset &= 0x1fff;
	}
	out->ttl = in->ttl;
	out->protocol = in->protocol;
	out->checksum = ntohs(in->checksum);
	addr.s_addr = in->src_ip;
	strncpy(out->src_ip, inet_ntoa(addr), STR_IP_SIZE);
	addr.s_addr = in->dest_ip;
	strncpy(out->dest_ip, inet_ntoa(addr), STR_IP_SIZE);
	return 0;
}

int pack_ip_header(const ip_header_t * in, ip_header * out) {
	if (!in || !out) return -1;
	memset(out, 0, sizeof(ip_header));
	out->version = in->version;
	out->hlen = in->hlen;
	out->tos_pri = in->tos_pri;
	switch (in->tos_type) {
	case TOS_NONE:
		out->tos_type = 0;
		break;
	case MIN_DELAY:
		out->tos_type = 8;
		break;
	case MAX_THROUGHPUT:
		out->tos_type = 4;
		break;
	case MAX_USABILITY:
		out->tos_type = 2;
		break;
	case MIN_COST:
		out->tos_type = 1;
		break;
	default:
		return -1;
	}
	out->length = htons(in->length);
	out->id = htons(in->id);
	out->offset = in->offset;
	switch (in->frag) {
	case DONT_FRAG:
		out->offset &= 0x5fff;
		break;
	case MORE_FRAG:
		out->offset &= 0x3fff;
		break;
	default:
		out->offset &= 0x1fff;
		break;
	}
	out->offset = htons(in->offset);
	out->ttl = in->ttl;
	out->protocol = in->protocol;
	out->checksum = htons(in->checksum);
	out->src_ip = inet_addr(in->src_ip);
	out->dest_ip = inet_addr(in->dest_ip);
	return 0;
}

static const char * ip_tos_type(enum tos_enum type) {
	switch (type) {
	case MIN_DELAY:
		return "minimum delay";
	case MAX_THROUGHPUT:
		return "max throughput";
	case MAX_USABILITY:
		return "max usability";
	case MIN_COST:
		return "minum cost";
	default:
		return "none";
	}
}

static const char * ip_fragment_flag(enum frag_enum flag) {
	switch (flag) {
	case DONT_FRAG:
		return "don't fragment";
	case MORE_FRAG:
		return "more fragment";
	case END_FRAG:
		return "end fragment";
	}
}

static const char * ip_proto_type(unsigned char proto) {
	switch (proto) {
	case IPPROTO_TCP:
		return "TCP";
	case IPPROTO_UDP:
		return "UDP";
	case IPPROTO_ICMP:
		return "ICMP";
	case IPPROTO_IGMP:
		return "IGMP";
	default:
		return "OTHER";
	}
}

const char * str_ip_header(const ip_header_t * in) {
	char * ptr;
	static char buf[1024];
	int n = 0, l = sizeof(buf) - 1;
	if (!in) return "";
	ptr = buf;
	n = snprintf(ptr, l, "    Ip version: %u\n", in->version);
	l -= n; ptr += n;
	n = snprintf(ptr, l, "    Ip head length: %u*4 bytes\n", in->hlen);
	l -= n; ptr += n;
	n = snprintf(ptr, l, "    Tos priority: %u\n", in->tos_pri);
	l -= n; ptr += n;
	n = snprintf(ptr, l, "    Tos type: %s(%u)\n", ip_tos_type(in->tos_type), in->tos_type);
	l -= n; ptr += n;
	n = snprintf(ptr, l, "    Length: %ubytes\n", in->length);
	l -= n; ptr += n;
	n = snprintf(ptr, l, "    Ip packet id: %u\n", in->id);
	l -= n; ptr += n;
	n = snprintf(ptr, l, "    Fragment flag: %s\n", ip_fragment_flag(in->frag));
	if (in->frag != DONT_FRAG) {
		l -= n; ptr += n;
		n = snprintf(ptr, l, "    Ip packet offset: %u\n", in->id);
	}
	l -= n; ptr += n;
	n = snprintf(ptr, l, "    TTL: %u\n", in->ttl);
	l -= n; ptr += n;
	n = snprintf(ptr, l, "    Protocol type: %s(%u)\n", ip_proto_type(in->protocol), in->protocol);
	l -= n; ptr += n;
	n = snprintf(ptr, l, "    Checksum: %u\n", in->checksum);
	l -= n; ptr += n;
	n = snprintf(ptr, l, "    Source ip addr: %s\n", in->src_ip);
	l -= n; ptr += n;
	n = snprintf(ptr, l, "    Destination ip addr: %s\n", in->dest_ip);
	return buf;
}


int parse_tcp_header(const tcp_header * in, tcp_header_t * out) {
	if (!in || !out) return -1;
	memset(out, 0, sizeof(tcp_header_t));
	out->src_port = ntohs(in->src_port);
	out->dest_port = ntohs(in->dest_port);
	out->seq = ntohl(in->seq);
	out->ack = ntohl(in->ack);
	out->hlen = in->hlen;
	if (in->ctlflag & 0x20)
		out->urg_flag = 1;
	if (in->ctlflag & 0x10)
		out->ack_flag = 1;
	if (in->ctlflag & 0x08)
		out->push_flag = 1;
	if (in->ctlflag & 0x04)
		out->rst_flag = 1;
	if (in->ctlflag & 0x02)
		out->syn_flag = 1;
	if (in->ctlflag & 0x01)
		out->fin_flag = 1;
	out->win = ntohs(in->win);
	out->checksum = ntohs(in->checksum);
	out->urgptr = ntohs(in->urgptr);
	return 0;
}

int pack_tcp_header(const tcp_header_t * in, tcp_header * out) {
	if (!in || !out) return -1;
	memset(out, 0, sizeof(tcp_header));
	out->src_port = htons(in->src_port);
	out->dest_port = htons(in->dest_port);
	out->seq = htonl(in->seq);
	out->ack = htonl(in->ack);
	out->hlen = in->hlen;
	if (in->urg_flag)
		out->ctlflag += 0x20;
	if (in->ack_flag)
		out->ctlflag += 0x10;
	if (in->push_flag)
		out->ctlflag += 0x08;
	if (in->rst_flag)
		out->ctlflag += 0x04;
	if (in->syn_flag)
		out->ctlflag += 0x02;
	if (in->fin_flag)
		out->ctlflag += 0x01;
	out->win = htons(in->win);
	out->checksum = htons(in->win);
	out->urgptr = htons(in->urgptr);
	return 0;
}

const char * str_tcp_header(const tcp_header_t * in) {
	char * ptr;
	static char buf[1024];
	int n = 0, l = sizeof(buf) - 1;
	if (!in) return "";
	ptr = buf;
	n = snprintf(ptr, l, "    Source port: %u\n", in->src_port);
	l -= n; ptr += n;
	n = snprintf(ptr, l, "    Destination port: %u\n", in->dest_port);
	l -= n; ptr += n;
	n = snprintf(ptr, l, "    Tcp head length: %u\n", in->hlen * 4);
	l -= n; ptr += n;
	n = snprintf(ptr, l, "    Seq: %u\n", in->seq);
	if (in->ack_flag) {
		l -= n; ptr += n;
		n = snprintf(ptr, l, "    ACK: %u\n", in->ack);
	}
	if (in->push_flag) {
		l -= n; ptr += n;
		n = snprintf(ptr, l, "    PUSH is set\n");
	}
	if (in->rst_flag) {
		l -= n; ptr += n;
		n = snprintf(ptr, l, "    RST is set\n");
	}
	if (in->syn_flag) {
		l -= n; ptr += n;
		n = snprintf(ptr, l, "    SYN is set\n");
	}
	if (in->fin_flag) {
		l -= n; ptr += n;
		n = snprintf(ptr, l, "    FIN is set\n");
	}
	l -= n; ptr += n;
    n = snprintf(ptr, l, "    Window size: %u\n", in->win);
	l -= n; ptr += n;
    n = snprintf(ptr, l, "    Checksum: %u\n", in->checksum);
	if (in->urg_flag) {
		l -= n; ptr += n;
		n = snprintf(ptr, l, "    Urgent ptr: %u\n", in->urgptr);
	}
	return buf;
}


