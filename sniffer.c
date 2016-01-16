/**
 * @file sniffer.c
 * @brief    
 * @author GongZhaohui
 * @version
 * @date 2016-01-15
 */
#include "sniffer.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

static int set_promisc(socket_t so, char * ifname, char enable) {
    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(so, SIOCGIFFLAGS, &ifr) < 0) {
        printf("%s- ERROR while getting interface flags\n", ifname);
        return -1;
    }
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (enable)
        ifr.ifr_flags |= IFF_PROMISC;
    else
        ifr.ifr_flags &= ~IFF_PROMISC;
    if (ioctl(so, SIOCSIFFLAGS, &ifr) < 0) {
        perror("set_promisc- ioctl set IFF_PROMISC failed");
        return -1;
    }
    return 0;
}

static int do_sniff(sniffer * p) {
    int n_recv = 0;
    char buf[2048];
    if (!p) return -1;
recv_again:
    n_recv = 0;
    n_recv = recv(p->so, buf, sizeof(buf), 0);
    if (n_recv < 0) {
        perror("do_sniff- recv failed");
        return -1;
    } else if (n_recv > 0) {
        (p->handler)(p, buf, n_recv);
    }
    if (!p->exit)
        goto recv_again;
    return 0;
}

int init_sniffer(sniffer * p, int speed, int port, char * ifname, sniff_handler handler) {
    if (!p) return -1;
    if (port < 0 || port > 65535) {
        printf("init_sniffer- invalid port number\n");
        return -1;
    }
    if (!ifname) {
        printf("init_sniffer- input ifname is null\n");
        return -1;
    }
    p->exit = 1;
    p->speed = (speed > 0)? speed : 0;
    p->handler = handler;
    strncpy(p->ifname, ifname, sizeof(p->ifname));
    p->ifname[sizeof(p->ifname) - 1] = 0;
    p->so = -1;
    return 0;
}

int sniffer_open(sniffer * p) {
    int ret = 0;
    socket_t so = -1;
    if (!p) return -1;
    if (p->so != -1) {
        printf("sniffer_open- sniffer is not inited\n");
        return -1;
    }
    // recv all ip packets which pass through the if
    //so = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    //so = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    so = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (so < 0) {
        perror("sniffer_open- socket() failed");
        return -1;
    }
    // set promisc mode of the interface
    ret = set_promisc(so, p->ifname, 1);
    if (ret) {
        perror("sniffer_open- set_promisc() failed\n");
        close(so);
        return -1;
    }
    p->so = so;
    return 0;
}

void sniffer_close(sniffer * p) {
    if (p) {
        p->exit = 1;
        if (p->so >= 0) {
            // unset promisc mode of the interface
            set_promisc(p->so, p->ifname, 0);
            close(p->so);
            p->so = -1;
        }
    }
}

void stop_sniff(sniffer * p_sniffer) {
    if (p_sniffer) p_sniffer->exit = 1;
}

int start_sniff(sniffer * p_sniffer) {
    if (!p_sniffer) return -1;
    if (p_sniffer->so < 0) {
        printf("start_sniff- the sniffer is not opened\n");
        return -1;
    }
    p_sniffer->exit = 0;
    return do_sniff(p_sniffer);
}





