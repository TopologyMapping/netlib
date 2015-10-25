#ifndef __SENDER_H__
#define __SENDER_H__

#include <inttypes.h>
#include "packet.h"

struct sender4;

struct sender4 * sender4_create(const char *device);
void sender4_destroy(struct sender4 *sender);

/* `padding` will be rounded to the next even integer. */
struct packet * sender4_send_icmp(struct sender4 *sender,
		uint32_t dst, uint8_t ttl,
		uint16_t ipid,
		uint16_t icmpsum, uint16_t icmpid, uint16_t icmpseq,
		size_t padding);

/* `padding` will be rounded to the next even integer. */
struct packet * sender4_send_icmp_fixrev(struct sender4 *sender,
		uint32_t dst, uint8_t ttl,
		uint16_t ipid,
		uint16_t icmpsum, uint16_t rev_icmpsum, uint16_t icmpseq,
		size_t padding);

#endif
