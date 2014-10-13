#ifndef __PACKET_H__
#define __PACKET_H__

#include <inttypes.h>
#include <time.h>
#include <libnet.h>

struct packet {/*{{{*/
	struct timespec tstamp;
	uint8_t *buf;
	size_t buflen;

    uint8_t ipType; // ipType = 4 to IPv4; ipType = 6 to IPv6;
	struct libnet_ipv4_hdr *ip;
	struct libnet_ipv6_hdr *ipv6;

	union {
		struct libnet_icmpv4_hdr *icmp;
		struct libnet_icmpv6_hdr *icmpv6;
		struct libnet_udp_hdr *udp;
		struct libnet_tcp_hdr *tcp;
	};
	uint8_t *payload;
};/*}}}*/

struct packet * packet_create_eth(const uint8_t *ethbuf, size_t buflen, int ipType);
struct packet * packet_create_ip(const uint8_t *ipbuf, size_t buflen, int ipType);
struct packet * packet_clone(const struct packet *orig);
void packet_destroy(struct packet *pkt);
char * packet_tostr(const struct packet *pkt);

#endif
