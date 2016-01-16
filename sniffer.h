/**
 * @file sniffer.h
 * @brief	
 *
 * @author GongZhaohui
 * @version 
 * @date 2016-01-15
 */
#ifndef _SNIFFER_H_
#define _SNIFFER_H_

#include "tcpipproto.h"
#include <net/if.h>

struct sniffer_entry; 
typedef void (*sniff_handler)(struct sniffer_entry *p_sniffer, char * data, unsigned len);

typedef struct sniffer_entry {
	char exit;        // if not 0 then exit sniff
	int speed;        // sniff speed control, if 0 not control
	socket_t so;      // socket handle for sniffer
	int sniff_port;   // sniff port on the interface
	char ifname[IFNAMSIZ + 1];  // interface name
	sniff_handler handler; // callback of got packets
} sniffer;

int init_sniffer(sniffer * p, int speed, int port, char * ifname, sniff_handler handler);

int sniffer_open(sniffer * p_sniffer);

void sniffer_close(sniffer * p_sniffer);

void stop_sniff(sniffer * p_sniffer);

int start_sniff(sniffer * p_sniffer);


#endif

