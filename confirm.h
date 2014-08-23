#ifndef __CONFIRM_H__
#define __CONFIRM_H__

/* the confirmation module receives queries to send packets toward a
 * destination with a given ttl, a given flow identifier, and a maximum number
 * of retransmissions. when an answer is received or after all retransmissions
 * have timed out, a callback function will be called informing the results. */

#include <inttypes.h>

struct confirm_query {
	/* query fields. must be filled by the caller: */
	uint32_t dst;
	uint8_t ttl;
	uint8_t flowid;
	uint8_t ntries;
	void (*cb)(struct confirm_query *query);
	void *data;

	/* answer fields. ip unset and trynum == ntries+1 if no answer: */
	uint32_t ip;
	uint8_t trynum;

	struct timespec probetime;
	struct timespec timeout;
	struct timespec start;
	struct timespec lastpkt;
	struct timespec answertime;
	void *event;
};

struct confirm;
typedef void confirm_query_cb(struct confirm_query *query);

/* will open a libnet sender on the given device and wait for queries. */
struct confirm * confirm_create(const char *device, uint16_t icmpid);
void confirm_destroy(struct confirm *confirm);

void confirm_query(struct confirm *confirm, struct confirm_query *query);

struct confirm_query * confirm_query_create(uint32_t dst, uint8_t ttl,
		uint8_t flowid);
void confirm_query_destroy(struct confirm_query *query);

#endif
