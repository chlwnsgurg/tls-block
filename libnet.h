#include <stdint.h>
#include <netinet/in.h>

#define TCP_LEN 20
#define IP_LEN 20
#define ETH_LEN 14

struct LEN_ARGS{
	uint32_t ip_len;
	uint32_t tcp_len;
	uint32_t tcp_data_len;
};

struct my_hdr{
        uint32_t src;
       	uint32_t dst;
       	uint8_t ph;
       	uint8_t pro;
       	uint16_t tcp_len;
};



/* ethernet addresses are 6 octets long */
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN      0x6
#endif

/*
 *  Ethernet II header
 *  Static header size: 14 bytes
 */
struct libnet_ethernet_hdr {
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#endif

/*
 *  IPv4 header
 *  Internet Protocol, version 4
 *  Static header size: 20 bytes
 */
 struct libnet_ipv4_hdr {

    u_int8_t ip_hl:4,ip_v:4; /* header length | version */
    u_int8_t ip_tos;       /* type of service */
    u_int16_t ip_len;        /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
#ifndef IPTYPE_TCP
#define IPTYPE_TCP      0x06  /* Transmission Control Protocol */
#endif
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */

/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t th_x2:4,th_off:4;  /* (unused) | data offset */
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif

    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};