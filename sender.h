#ifndef __SENDER_H__
#define __SENDER_H__

#include <inttypes.h>
#include "packet.h"

struct sender;

struct sender * sender_create(const char *device, int ipType);
void sender_destroy(struct sender *sender);

/* if odd, padding will be rounded to the next even integer */
struct packet * sender_send_icmp(struct sender *sender,
		struct sockaddr *dst, uint8_t ttl, uint16_t ipid,
		uint16_t icmpsum, uint16_t icmpid, uint16_t icmpseq,
		size_t padding);

struct packet * sender_send_icmp_fixrev(struct sender *sender,
		uint32_t dst, uint8_t ttl, uint16_t ipid,
		uint16_t icmpsum, uint16_t rev_icmpsum, uint16_t icmpseq,
		size_t padding);

struct libnet_in6_addr nameToAddr6WithSender (struct sender *s, char* dst);

#endif
