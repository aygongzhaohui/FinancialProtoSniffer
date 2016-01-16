#ifndef _SOCKET_DEF_H_
#define _SOCKET_DEF_H_

#include <stdint.h>

typedef int socket_t;

typedef struct tag_ip_header {
	unsigned version : 4;
	unsigned hlen : 4;
	unsigned tos_pri : 3;
	unsigned tos_type : 4;
	unsigned tos_nop : 1;
	uint16_t length;
	uint16_t id;
	uint16_t offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t src_ip;
	uint32_t dest_ip;
	uint32_t option[0];
} ip_header;

enum tos_enum { MIN_DELAY, MAX_THROUGHPUT, MAX_USABILITY, MIN_COST };

typedef struct tag_ip_header_t {
	char version;
	char hlen;
	enum tos_enum tos_type;
	unsigned short length;
	unsigned short id;
} ip_header_t;


#endif

