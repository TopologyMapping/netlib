#ifndef __SENDER6_H__
#define __SENDER6_H__

#include <inttypes.h>
#include "packet.h"

struct sender6;

struct sender6 * sender6_create(const char *device);
void sender6_destroy(struct sender6 *sender);

/* `padding` will be rounded to the next even integer. */
struct packet * sender6_send_icmp(struct sender6 *s, /* {{{ */
		struct libnet_in6_addr dst, uint8_t ttl,
		uint8_t traffic_class, uint32_t flow_label,
		uint16_t icmpsum, uint16_t icmpid, uint16_t icmpseq,
		size_t padding);

/* not implemented:
struct packet * sender6_send_icmp_fixrev(struct sender6 *sender,
		struct libnet_in6_addr dst, uint8_t ttl, uint16_t ipid,
		uint16_t icmpsum, uint16_t rev_icmpsum, uint16_t icmpseq,
		size_t padding);
*/

struct packet * sender6_send_tcp(struct sender6 *s, struct libnet_in6_addr dst,
		uint8_t ttl, uint8_t traffic_class, uint32_t flow_label, uint16_t sp,
		uint16_t dp, uint32_t seq_number, uint32_t ack_number,
		uint8_t control_flags, uint16_t window_size);

#endif
