#ifndef _TCPIP_PROTO_H_
#define _TCPIP_PROTO_H_

#include <stdint.h>
#include <netinet/in.h>
#include <asm/byteorder.h>

#define MAC_SIZE       (6)
#define STR_IP_SIZE    (15)
#define ETH_HEAD_LEN   (14)
#define ETH_T_IP      (0x0800)
#define ETH_T_ARPREQ   (0x0806)
#define ETH_T_ARPRSP   (0x0835)

typedef int socket_t;

//////////////////////////////// Ethernet /////////////////////////////
typedef struct tag_eth_header {
	uint8_t src_mac[MAC_SIZE];
	uint8_t dest_mac[MAC_SIZE];
	uint16_t type_len;
} eth_header;

typedef eth_header eth_header_t;

int parse_eth_header(const eth_header * in, eth_header_t * out);
int pack_eth_header(const eth_header_t * in, eth_header * out);
const char * str_eth_header(const eth_header_t * in);


//////////////////////////////// IP /////////////////////////////
typedef struct tag_ip_header {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	unsigned hlen : 4;
	unsigned version : 4;
	unsigned tos_nop : 1;
	unsigned tos_type : 4;
	unsigned tos_pri : 3;
#elif defined(__BIG_ENDIAN_BITFIELD)
	unsigned version : 4;
	unsigned hlen : 4;
	unsigned tos_pri : 3;
	unsigned tos_type : 4;
	unsigned tos_nop : 1;
#else
	#error  "Please fix <asm/byteorder.h>"
#endif
	uint16_t length;
	uint16_t id;
	uint16_t offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t src_ip;
	uint32_t dest_ip;
} ip_header;

// tos values
enum tos_enum { TOS_NONE, MIN_DELAY, MAX_THROUGHPUT, MAX_USABILITY, MIN_COST };
// fragment flag
enum frag_enum { DONT_FRAG, MORE_FRAG, END_FRAG };
typedef struct tag_ip_header_t {
	unsigned char version;
	unsigned char hlen;
	unsigned char tos_pri;
	enum tos_enum tos_type;
	unsigned short length;
	unsigned short id;
	unsigned short offset;
	enum frag_enum frag;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	char src_ip[STR_IP_SIZE + 1];
	char dest_ip[STR_IP_SIZE + 1];
} ip_header_t;

int parse_ip_header(const ip_header * in, ip_header_t * out);
int pack_ip_header(const ip_header_t * in, ip_header * out);
const char * str_ip_header(const ip_header_t * in);


//////////////////////////////// TCP /////////////////////////////
typedef struct tag_tcp_header {
	uint16_t src_port; 
	uint16_t dest_port;
	uint32_t seq;
	uint32_t ack;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	unsigned : 4;
	unsigned hlen : 4;
    unsigned ctlflag : 6;
	unsigned : 2;
#elif defined(__BIG_ENDIAN_BITFIELD)
	unsigned hlen : 4;
	unsigned : 4;
	unsigned : 2;
    unsigned ctlflag : 6;
#else
	#error  "Please fix <asm/byteorder.h>"
#endif
	uint16_t win;
	uint16_t checksum;
	uint16_t urgptr;
} tcp_header;

typedef struct tag_tcp_header_t {
	unsigned short src_port;
	unsigned short dest_port;
	unsigned int seq;
	unsigned int ack;
	unsigned char hlen;
	unsigned char urg_flag;
	unsigned char ack_flag;
	unsigned char push_flag;
	unsigned char rst_flag;
	unsigned char syn_flag;
	unsigned char fin_flag;
	unsigned short win;
	unsigned short checksum;
	unsigned short urgptr;
} tcp_header_t;

int parse_tcp_header(const tcp_header * in, tcp_header_t * out);
int pack_tcp_header(const tcp_header_t * in, tcp_header * out);
const char * str_tcp_header(const tcp_header_t * in);


typedef struct tag_bits {
	unsigned bit0 : 1;
	unsigned bit1 : 1;
	unsigned bit2 : 1;
	unsigned bit3 : 1;
	unsigned bit4 : 1;
	unsigned bit5 : 1;
	unsigned bit6 : 1;
	unsigned bit7 : 1;
} bits;


#endif

