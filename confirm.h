#ifndef __CONFIRM_H__
#define __CONFIRM_H__

/* the confirmation module receives queries to send packets toward
 * a destination with a given ttl, a given flow identifier, and
 * a maximum number of retransmissions.  when an answer is received
 * or after all retransmissions have timed out, a callback function
 * will be called informing the results. */

#include <inttypes.h>
#include "packet.h"

struct confirm_query {/*{{{*/
	/* query fields ******************/
	/* must be filled by the caller: */
	struct sockaddr_storage dst; // check dst.sa_family
	int type;
	uint8_t ttl;

	union {
		/* `ip4_id` is not used to identify probes (in
		 * `confirm_query_cmp`) as it is not returned in
		 * `ECHO_REPLY` packets. */
		uint16_t ipid;
		struct {
			uint8_t traffic_class;
			uint32_t flow_label;
		};
	};

	union {
		struct {
			uint16_t src_port;
			uint16_t dst_port;
		} tcp;

		struct {
			uint16_t icmpid;
		} icmp;
	};
	
			 /* uint16_t icmpseq used to identify probes */
	uint8_t flowid;  /* forward ICMP checksum */
	uint8_t revflow; /* reverse flow ID, ipv4 only, uses ipid */

	size_t padding; /* amount of zeroed bytes to append in the probe */

	int ntries;
	void (*cb)(struct confirm_query *query);
	void *data;

	/* answer fields *********************************/
	/* ip unset and trynum == ntries+1 if no answer: */
	int trynum;
	struct sockaddr_storage ip;

	struct timespec probetime;
	struct timespec timeout;
	struct timespec start;
	struct timespec lastpkt;
	struct timespec answertime;
	void *event;

	struct packet *probe;
	struct packet *response;
};/*}}}*/

struct confirm;
typedef void confirm_query_cb(struct confirm_query *query);

/* `confirm_create` will open a `libnet` sender on the given device
 * and wait for queries. */
struct confirm * confirm_create(const char *device);
void confirm_destroy(struct confirm *confirm);

void confirm_submit(struct confirm *confirm, struct confirm_query *query);

struct confirm_query * confirm_query_create4(
		const struct sockaddr_storage *dst,
		uint8_t ttl,
		uint16_t ipid,
		uint16_t icmpid, uint8_t flowid,
		uint8_t revflow,
		confirm_query_cb cb);

struct confirm_query *confirm_query_create6_tcp(
		const struct sockaddr_storage *dst,
		uint8_t ttl,
		uint8_t traffic_class,
		uint32_t flow_label,
		uint8_t flowid,
		uint16_t src_port,
		uint16_t dst_port,
		confirm_query_cb cb);

struct confirm_query *confirm_query_create6_icmp(
		const struct sockaddr_storage *dst,
		uint8_t ttl,
		uint8_t traffic_class,
		uint32_t flow_label,
		uint16_t icmpid,
		uint8_t flowid,
		confirm_query_cb cb);

void confirm_query_destroy(struct confirm_query *query);

#endif
