#ifndef __PACKET_H__
#define __PACKET_H__

#include <inttypes.h>
#include <time.h>
#include <libnet.h>

struct packet {/*{{{*/
	struct timespec tstamp;
	uint8_t *buf;
	size_t buflen;

	uint8_t ipversion;
	union {
		struct libnet_ipv4_hdr *ip;
		struct libnet_ipv6_hdr *ipv6;
	};
	union {
		struct libnet_icmpv4_hdr *icmp;
		struct libnet_icmpv6_hdr *icmpv6;
		struct libnet_udp_hdr *udp;
		struct libnet_tcp_hdr *tcp;
	};
	uint8_t *payload;
};/*}}}*/

struct packet * packet_create_eth(const uint8_t *ethbuf, size_t buflen);
struct packet * packet_create_ip(const uint8_t *ipbuf, size_t buflen);
struct packet * packet_clone(const struct packet *orig);
void packet_destroy(struct packet *pkt);
char * packet_tostr(const struct packet *pkt);

/* `sockaddr` is a convenience function to get a string for `sin`.
 * the returned string must be freed by the caller. */
char * sockaddr_tostr(const struct sockaddr_storage *sin);

/* `sockaddr_cmp` compares two sockaddr structs, first by
 * `sa_family`, then by address.  `dummy` result is for `libavl`
 * compatibility. */
int sockaddr_cmp(const void *vs1, const void *vs2, void *dummy);

#endif
