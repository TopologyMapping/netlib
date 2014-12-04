#ifndef __CONFIRM_H__
#define __CONFIRM_H__

/* the confirmation module receives queries to send packets toward a
 * destination with a given ttl, a given flow identifier, and a maximum number
 * of retransmissions. when an answer is received or after all retransmissions
 * have timed out, a callback function will be called informing the results. */

#include <inttypes.h>
#include "packet.h"

struct confirm_query {/*{{{*/
	/* query fields. must be filled by the caller: */
	struct sockaddr *dst;
	uint8_t ttl;
	uint16_t ipid;
	/* =ipid is not used to identify probes (in =confirm_query_cmp) as it
	 * is not returned in ECHO_REPLY packets. */
	uint16_t icmpid; /* icmpid == 0 fixes reverse flow id =revflow */
	/* uint16_t icmpseq used to identify probes */
	uint8_t flowid; /* forward ICMP checksum */
	size_t padding; /* amount of zeroed bytes to append in the probe */

	uint8_t revflow; /* reverse flow ID, uses ipid */

	int ntries;
	void (*cb)(struct confirm_query *query);
	void *data;

	/* answer fields. ip unset and trynum == ntries+1 if no answer: */
	int trynum;
    struct sockaddr *ip;

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

/* will open a libnet sender on the given device and wait for queries. */
struct confirm * confirm_create(const char *device, int ipversion);
void confirm_destroy(struct confirm *confirm);

void confirm_query(struct confirm *confirm, struct confirm_query *query);

struct confirm_query * confirm_query_create(struct sockaddr *dst, uint8_t ttl,
		uint16_t ipid, uint16_t icmpid,
		uint8_t flowid, uint8_t revflow,
		confirm_query_cb cb);


void confirm_query_destroy(struct confirm_query *query);

struct libnet_in6_addr nameToAddr6WithConfirm (struct confirm *c, char* dst);

#endif
