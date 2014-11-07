#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <assert.h>

#include <sys/types.h>
#include <arpa/inet.h>

#include <libnet.h>
#include <limits.h>

#include "dlist.h"
#include "pavl.h"
#include "log.h"
#include "demux.h"
#include "sender.h"
#include "timespec.h"
#include "confirm.h"

#define EVENT_QUERY 1
#define EVENT_SENDPACKET 2
#define EVENT_TIMEOUT 3
#define EVENT_ANSWER 4

#define CONFIRM_MAX_FLOWID 0x7F

static uint16_t id2checksum[] = {
14717, 22388, 62313, 10176,
21560, 58498, 51533, 57446,
40214, 58836, 61020, 60303,
47362, 15783, 26594, 52986,
46982, 28604, 17977, 40763,
45778, 55128, 26742, 10303,
11846, 24062, 61651, 36311,
28739, 18774, 41508, 36980,

31971, 10291, 58372, 22803,
28260, 20249, 44783, 56362,
30046, 62710, 13161, 26487,
34819, 56020, 25968, 47549,
20159, 55610, 10461, 15074,
55634, 49444, 27442, 48528,
51107, 20766, 15538, 17013,
28251, 34891, 47459, 36010,

55056, 49555, 60057, 61378,
51847, 37347, 48128, 64868,
19631, 55982, 20553, 43798,
11415, 37099, 31327, 44618,
59767, 12017, 28075, 55326,
51554, 10252, 43790, 24168,
34406, 22283, 28853, 63102,
16476, 13325, 46141, 21589,

53972, 41407, 28252, 42641,
64488, 23557, 51371, 43890,
63920, 44184, 49155, 16973,
38159, 32258, 30160, 54308,
45073, 39191, 34214, 62805,
29658, 52652, 12494, 35303,
32933, 21531, 46111, 34771,
54288, 21079, 35268, 21930,

61150, 15134, 60113, 33221,
39086, 42237, 35476, 41452,
60931, 36767, 61754, 59867,
15512, 57323, 25173, 13462,
30214, 10870, 64463, 26465,
25704, 15422, 19623, 62475,
36662, 43311, 43346, 36049,
32483, 10407, 54508, 40802,

56660, 25312, 32663, 28554,
10869, 46846, 58134, 13695,
57809, 57985, 34286, 25982,
59172, 64492, 59851, 32071,
50155, 61813, 41564, 56041,
22857, 28926, 52844, 31751,
59761, 40828, 11152, 36488,
49841, 60726, 61568, 49960,

62612, 42308, 12330, 25132,
32544, 62201, 40360, 25926,
23779, 46994, 51287, 60757,
27098, 50797, 35247, 27674,
38735, 13603, 37206, 56370,
44398, 39156, 23573, 49705,
59775, 28304, 30738, 28995,
11806, 27574, 57370, 49452,

30534, 30315, 15176, 25333,
50734, 57231, 58877, 28966,
61247, 63417, 64232, 38876,
57028, 31516, 11744, 51993,
53051, 56348, 64887, 14159,
15097, 36141, 31282, 61073,
31335, 33431, 26729, 30052,
31524, 13896, 44086, 57018,

48943, 18671, 33573, 58068,
64486, 36483, 62043, 15546,
28299, 49128, 61995, 23337,
33232, 17255, 24542, 61045,
54914, 50044, 42092, 36959,
29529, 15482, 65224, 11319,
24629, 63925, 56980, 61071,
51503, 26377, 10268, 54357
};

/*****************************************************************************
 * declarations
 ****************************************************************************/
struct confirm {
	pthread_t thread;
	pthread_mutex_t evlist_mut;
	struct dlist *evlist;
	pthread_cond_t event_cond;
	struct sender *sender;
	struct pavl_table *events;
	struct pavl_table *queries;
};

struct event {
	unsigned type;
	struct timespec time;
	struct confirm_query *query;
};

static void * confirm_thread(void *vconfirm);
static int confirm_recv(const struct packet *packet, void *confirm);
static void confirm_sendevent(struct confirm *confirm, struct event *ev);

static void confirm_mutex_unlock(void *vmutex);

static struct event * event_create(unsigned type, struct confirm_query *query);
static void event_destroy(struct event *event);
static void event_destroy_pavl(void *event, void *dummy);
static void event_destroy_void(void *ev);
static int event_cmp(const void *a, const void *b, void *dummy);
static int event_cmp(const void *a, const void *b, void *dummy);

static void event_run(struct confirm *confirm, struct event *event);
static void event_run_schednext(struct confirm *conf,
		struct confirm_query *query);
static void event_run_query(struct confirm *conf, struct event *ev);
static void event_run_sendpacket(struct confirm *conf, struct event *ev);
static void event_run_timeout(struct confirm *conf, struct event *ev);
static int event_run_answer_testtimeout(const struct confirm_query *query,
		struct timespec packet);
static void event_run_answer(struct confirm *conf, struct event *ev);

static void query_destroy_pavl(void *query, void *dummy);
static int query_cmp(const void *a, const void *b, void *dummy);

static uint16_t confirm_data_pack(uint8_t ttl, uint8_t fwflow, int fixrev);
static void confirm_data_unpack(uint16_t data, uint8_t *ttl, uint8_t *fwflow,
				int *fixrev);
uint8_t confirm_inverse_flowid(uint16_t chksum);

/*****************************************************************************
 * public functions
 ****************************************************************************/
struct confirm * confirm_create(const char *device) /* {{{ */
{
	struct confirm *confirm;

	confirm = malloc(sizeof(struct confirm));
	if(!confirm) logea(__FILE__, __LINE__, NULL);

	confirm->events = pavl_create(event_cmp, NULL, NULL);
	if(!confirm->events) goto out;
	confirm->queries = pavl_create(query_cmp, NULL, NULL);
	if(!confirm->queries) goto out_events;

	pthread_mutex_init(&confirm->evlist_mut, NULL);
	pthread_cond_init(&confirm->event_cond, NULL);

	confirm->evlist = dlist_create();
	if(!confirm->evlist) goto out_cond;

	confirm->sender = sender_create(device);
	if(!confirm->sender) goto out_evlist;
	if(pthread_create(&confirm->thread, NULL, confirm_thread, confirm)) {
		goto out_sender;
	}

	demux_listener_add(confirm_recv, confirm);

	logd(LOG_INFO, "%s dev=%s ok\n", __func__, device);
	return confirm;

	out_sender:
	loge(LOG_DEBUG, __FILE__, __LINE__);
	sender_destroy(confirm->sender);
	out_evlist:
	loge(LOG_DEBUG, __FILE__, __LINE__);
	dlist_destroy(confirm->evlist, NULL);
	out_cond:
	loge(LOG_DEBUG, __FILE__, __LINE__);
	pavl_destroy(confirm->queries, NULL);
	pthread_mutex_destroy(&confirm->evlist_mut);
	pavl_destroy(confirm->queries, NULL);
	out_events:
	loge(LOG_DEBUG, __FILE__, __LINE__);
	pavl_destroy(confirm->events, NULL);
	out:
	loge(LOG_DEBUG, __FILE__, __LINE__);
	free(confirm);
	return NULL;
} /* }}} */

void confirm_destroy(struct confirm *confirm) /* {{{ */
{
	int i;
	void *r;
	logd(LOG_DEBUG, "entering %s\n", __func__);
	demux_listener_del(confirm_recv, confirm);

	if(pthread_cancel(confirm->thread)) loge(LOG_FATAL, __FILE__, __LINE__);
	i = pthread_join(confirm->thread, &r);
	if(i || r != PTHREAD_CANCELED)
		logd(5, "%s join(%s) ret(%p)\n", __func__, strerror(errno), r);
	if(pthread_mutex_destroy(&confirm->evlist_mut))
		logd(5, "%s event_mut %s\n", __func__, strerror(errno));
	if(pthread_cond_destroy(&confirm->event_cond))
		logd(5, "%s event_cond %s\n", __func__, strerror(errno));

	dlist_destroy(confirm->evlist, event_destroy_void);
	sender_destroy(confirm->sender);
	pavl_destroy(confirm->events, event_destroy_pavl);
	pavl_destroy(confirm->queries, query_destroy_pavl);
	free(confirm);
} /* }}} */

void confirm_query(struct confirm *confirm, struct confirm_query *query) { /* {{{ */
	struct event *ev = event_create(EVENT_QUERY, query);
	if(!ev) return;
	confirm_sendevent(confirm, ev);
} /* }}} */

int confirm_pkt_parse(const struct packet *pkt, uint32_t *dst, /*{{{*/
	       uint8_t *ttl, uint16_t *icmpid,
	       uint8_t *flowid, uint8_t *revflow, uint32_t *ip)
{
	if(pkt->ip->ip_p != IPPROTO_ICMP) return 0;

	if(pkt->icmp->icmp_type != ICMP_ECHOREPLY &&
			pkt->icmp->icmp_type != ICMP_TIMXCEED) {
		return 0;
	}

	*ip = pkt->ip->ip_src.s_addr;
	uint16_t data;
	uint16_t revsum;
	if(pkt->icmp->icmp_type == ICMP_ECHOREPLY) {
		*dst = pkt->ip->ip_src.s_addr;
		*icmpid = ntohs(pkt->icmp->icmp_id);
		data = ntohs(pkt->icmp->icmp_seq);
	} else if(pkt->icmp->icmp_type == ICMP_TIMXCEED) {
		if(pkt->icmp->icmp_code != ICMP_TIMXCEED_INTRANS) return 0;
		struct libnet_ipv4_hdr *rip;
		struct libnet_icmpv4_hdr *ricmp;
		rip = (struct libnet_ipv4_hdr *)(pkt->payload);
		ricmp = (struct libnet_icmpv4_hdr *)(pkt->payload + rip->ip_hl*4);
		*dst = rip->ip_dst.s_addr;
		*icmpid = ntohs(ricmp->icmp_id);
		revsum = ntohs(pkt->icmp->icmp_sum);
		data = ntohs(ricmp->icmp_seq);
	}
	int fixrev;
	confirm_data_unpack(data, ttl, flowid, &fixrev);
	if(fixrev) {
		*revflow = confirm_inverse_flowid(revsum);
		*icmpid = 0;
	} else {
		*revflow = 0;
	}
	return 1;
} /* }}} */

/*****************************************************************************
 * static functions
 ****************************************************************************/
static void * confirm_thread(void *vconfirm) /* {{{ */
{
	logd(LOG_INFO, "%s started\n", __func__);
	struct confirm *confirm = (struct confirm *)vconfirm;

	while(1) {
		int code;
		struct event *ev;

		pthread_mutex_lock(&confirm->evlist_mut);
		while(!dlist_empty(confirm->evlist)) {
			struct event *evv = dlist_pop_left(confirm->evlist);
			pthread_mutex_unlock(&confirm->evlist_mut);
			if(!evv) logea(__FILE__, __LINE__, "list empty");
			assert(evv->type == EVENT_QUERY ||
					evv->type == EVENT_ANSWER);
			event_run(confirm, evv);
			event_destroy(evv);
			pthread_mutex_lock(&confirm->evlist_mut);
		}

		pthread_cleanup_push(confirm_mutex_unlock,
				&(confirm->evlist_mut));
		if(pavl_count(confirm->events) == 0) {
			code = 0;
			ev = NULL;
			pthread_cond_wait(&confirm->event_cond,
					&confirm->evlist_mut);
		} else {
			struct pavl_traverser trav;
			ev = pavl_t_first(&trav, confirm->events);
			code = pthread_cond_timedwait(&confirm->event_cond,
					&confirm->evlist_mut, &ev->time);
		}
		pthread_cleanup_pop(0);

		/* processing timed-out event first, otherwise an EVENT_ANSWER
		 * for the timed-out event's query might happen and delete
		 * it from confirm->events. for reference,
		 * event_run_answer_testtimeout should check avoid this when
		 * ev->type == EVENT_TIMEOUT. however, we still need to
		 * consider the case when ev->type == EVENT_SENDPACKET. */
		pthread_mutex_unlock(&confirm->evlist_mut);
		if(code == ETIMEDOUT) {
			assert(ev);
			pavl_assert_delete(confirm->events, ev);
			event_run(confirm, ev);
			event_destroy(ev);
		}
	}
} /* }}} */

static void confirm_sendevent(struct confirm *confirm, struct event *ev) /* {{{ */
{
	pthread_mutex_lock(&confirm->evlist_mut);

	dlist_push_right(confirm->evlist, ev);
	pthread_cond_signal(&confirm->event_cond);

	pthread_mutex_unlock(&confirm->evlist_mut);
} /* }}} */

static int confirm_recv(const struct packet *pkt, void *vconfirm) /* {{{ */
{
	struct confirm *conf = (struct confirm *)vconfirm;
	struct confirm_query *query;
	struct event *event;
	uint32_t dst, ip;
	uint16_t icmpid;
	uint8_t ttl, flowid, revflow;

	if(!confirm_pkt_parse(pkt, &dst, &ttl, &icmpid, &flowid, &revflow, &ip)) {
		return 1;
	}

	query = confirm_query_create(dst, ttl, 0, icmpid, flowid, revflow, NULL);
	query->ip = ip;
	query->response = packet_clone(pkt);
	query->answertime = pkt->tstamp;
	event = event_create(EVENT_ANSWER, query);

	confirm_sendevent(conf, event);
	return 0;
} /* }}} */

uint8_t confirm_inverse_flowid(uint16_t chksum) {/*{{{*/
	int i;
	for(i = 0; i < CONFIRM_MAX_FLOWID; i++) {
		if(id2checksum[i] == chksum) return (uint8_t)i;
	}
	return 0xFF;
}/*}}}*/

static void confirm_mutex_unlock(void *vmutex) /* {{{ */
{
	pthread_mutex_unlock((pthread_mutex_t *)vmutex);
} /* }}} */

/*****************************************************************************
 * event functions {{{
 ****************************************************************************/
static struct event * event_create(unsigned type, struct confirm_query *query)
{
	struct event *event = malloc(sizeof(struct event));
	if(!event) logea(__FILE__, __LINE__, NULL);
	event->type = type;
	event->query = query;
	return event;
}

static void event_destroy(struct event *ev)
{
	free(ev);
}

static void event_destroy_void(void *ev)
{
	event_destroy(ev);
}

static void event_destroy_pavl(void *event, void *dummy)
{
	event_destroy((struct event *)event);
}

static int event_cmp(const void *a, const void *b, void *dummy)
{
	struct event *e1 = (struct event *)a;
	struct event *e2 = (struct event *)b;
	if(e1->time.tv_sec < e2->time.tv_sec) { return -1; }
	if(e1->time.tv_sec > e2->time.tv_sec) { return +1; }
	if(e1->time.tv_nsec < e2->time.tv_nsec) { return -1; }
	if(e1->time.tv_nsec > e2->time.tv_nsec) { return +1; }
	if(e1 < e2) { return -1; }
	if(e1 > e2) { return +1; }
	return 0;
} /* }}} */

/*****************************************************************************
 * event_run functions {{{
 ****************************************************************************/
static void event_run(struct confirm *confirm, struct event *event)
{
	switch(event->type) {
	case EVENT_QUERY:
		event_run_query(confirm, event);
		break;
	case EVENT_ANSWER: {
		event_run_answer(confirm, event);
		break;
	}
	case EVENT_SENDPACKET: {
		event_run_sendpacket(confirm, event);
		break;
	}
	case EVENT_TIMEOUT: {
		event_run_timeout(confirm, event);
		break;
	}
	default:
		logd(5, "%s unknown event type=%u\n", __func__, event->type);
		break;
	}
}

static void event_run_schednext(struct confirm *conf,
		struct confirm_query *query)
{
	struct event *newev;
	if(query->trynum < query->ntries) {
		newev = event_create(EVENT_SENDPACKET, query);
		query->event = newev;
		if(query->probetime.tv_sec == 0
				&& query->probetime.tv_nsec == 0) {
			newev->time = query->start;
			event_run_sendpacket(conf, newev);
			event_destroy(newev);
		} else {
			double rand = drand48() - 0.5;
			timespec_add(query->lastpkt, query->probetime,
					&newev->time);
			timespec_shift(query->probetime,
					rand * 0, /* shifting disabled */
					&newev->time);
			pavl_assert_insert(conf->events, newev);
		}
	} else {
		newev = event_create(EVENT_TIMEOUT, query);
		query->event = newev;
		timespec_add(query->lastpkt, query->timeout, &newev->time);
		pavl_assert_insert(conf->events, newev);
	}
}

static void event_run_query(struct confirm *conf, struct event *ev)
{
	struct confirm_query *query = ev->query;
	assert(ev->type == EVENT_QUERY);
	char addr[INET_ADDRSTRLEN];
	if(!inet_ntop(AF_INET, &query->dst, addr, INET_ADDRSTRLEN)) goto out;
	logd(LOG_EXTRA, "query dst=%s ttl=%d flowid=%d\n", addr, query->ttl,
				query->flowid);

	if(query->ntries == 0) goto out_noconfirm;
	if(pavl_find(conf->queries, query)) goto out_dup;

	query->trynum = 0;
	clock_gettime(CLOCK_REALTIME, &query->start);
	pavl_assert_insert(conf->queries, query);

	struct event *newev = event_create(EVENT_SENDPACKET, query);
	newev->time = query->start;
	event_run_sendpacket(conf, newev);
	event_destroy(newev);

	return;

	out_dup:
	logd(LOG_DEBUG, "%s duplicate query. dropped.\n", __func__);
	out_noconfirm:
	loge(LOG_DEBUG, __FILE__, __LINE__);
	query->cb(query);
	out:
	loge(LOG_DEBUG, __FILE__, __LINE__);
	return;
}

static void event_run_sendpacket(struct confirm *conf, struct event *ev)
{
	struct confirm_query *query = ev->query;
	assert(ev->type == EVENT_SENDPACKET);
	uint16_t data;

	/* TODO This function should store trynum in the probe so we know when
	 * each probe is answered and compute latencies.  But take care as we
	 * need to keep flowids fixed. */

	struct packet *pkt;
	if(query->icmpid) {
		data = confirm_data_pack(query->ttl, query->flowid, 0);
		pkt = sender_send_icmp(conf->sender, query->dst,
				query->ttl,
				query->ipid, id2checksum[query->flowid],
				query->icmpid, data, query->padding);
	} else {
		data = confirm_data_pack(query->ttl, query->flowid, 1);
		uint16_t revsum = id2checksum[query->revflow];
		pkt = sender_send_icmp_fixrev(conf->sender, query->dst,
				query->ttl,
				query->ipid, id2checksum[query->flowid],
				revsum, data, query->padding);
	}

	if(query->probe == NULL) { query->probe = pkt; }
	else { packet_destroy(pkt); }
	query->trynum++;
	query->lastpkt = ev->time;
	event_run_schednext(conf, query);
}

static void event_run_timeout(struct confirm *conf, struct event *ev)
{
	struct confirm_query *query = ev->query;
	assert(query->trynum == query->ntries);
	pavl_assert_delete(conf->queries, query);
	query->ip = UINT_MAX;
	query->cb(query);
}

static int event_run_answer_testtimeout(const struct confirm_query *query,
		struct timespec packet)
{
	struct timespec timeout, aux;
	timespec_mult(query->probetime, query->ntries-1, &aux);
	timespec_add(aux, query->timeout, &aux);
	timespec_add(query->start, aux, &timeout);
	if(timespec_cmp(packet, timeout) <= 0) return 1;
	timespec_sub(packet, timeout, &aux);
	logd(LOG_INFO, "%s packet missed timeout by ", __func__);
	char *ts = timespec_str(aux);
	logd(LOG_INFO, "tstamp %s\n", ts);
	free(ts);
	return 0;
}

static void event_run_answer(struct confirm *conf, struct event *ev)
{
	struct confirm_query *query;
	char dump[80];

	assert(ev->type = EVENT_ANSWER);
	query = pavl_find(conf->queries, ev->query);
	if(!query) goto out_spurious;

	if(!event_run_answer_testtimeout(query, ev->query->answertime)) {
		goto out;
	}

	query->ip = ev->query->ip;
	query->answertime = ev->query->answertime;
	query->response = ev->query->response;
	ev->query->response = NULL; /* avoid double free */
	confirm_query_destroy(ev->query);
	pavl_assert_delete(conf->queries, query);
	pavl_assert_delete(conf->events, query->event);
	event_destroy(query->event);
	query->cb(query);
	return;

	out_spurious:
	inet_ntop(AF_INET, &(ev->query->dst), dump, INET_ADDRSTRLEN);
	logd(5, "%s no query for dst=%s ttl=%d flowid=%d revflow=%d\n",
			__func__, dump,
			ev->query->ttl, ev->query->flowid,
			ev->query->revflow);
	out:
	confirm_query_destroy(ev->query);
} /* }}} */

/*****************************************************************************
 * query functions {{{
 ****************************************************************************/
struct confirm_query *
confirm_query_create(uint32_t dst, uint8_t ttl,
		uint16_t ipid, uint16_t icmpid,
		uint8_t flowid, uint8_t revflow,
		confirm_query_cb cb)
{
	struct confirm_query *query;

	query = malloc(sizeof(struct confirm_query));
	if(!query) logea(__FILE__, __LINE__, NULL);
	query->dst = dst;
	query->ttl = ttl;
	query->ipid = ipid;
	query->icmpid = icmpid;
	if(flowid > CONFIRM_MAX_FLOWID || revflow > CONFIRM_MAX_FLOWID) {
		logd(LOG_WARN, "%s,%d: flowid > 127!\n", __FILE__, __LINE__);
	}
	query->flowid = flowid & CONFIRM_MAX_FLOWID;
	query->padding = 0;
	query->revflow = (icmpid) ? 0 : revflow & CONFIRM_MAX_FLOWID;

	query->ntries = 1;
	query->cb = cb;
	query->data = NULL;

	query->ip = UINT_MAX;
	query->trynum = 0;

	query->probetime.tv_sec = 2;
	query->probetime.tv_nsec = 0;
	query->timeout.tv_sec = 5;
	query->timeout.tv_nsec = 0;
	query->start.tv_sec = 0;
	query->start.tv_nsec = 0;
	query->lastpkt.tv_sec = 0;
	query->lastpkt.tv_nsec = 0;
	query->answertime.tv_sec = 0;
	query->answertime.tv_nsec = 0;
	query->event = NULL;

	query->probe = NULL;
	query->response = NULL;
	return query;
}

void confirm_query_destroy(struct confirm_query *query)
{
	if(query->probe) packet_destroy(query->probe);
	if(query->response) packet_destroy(query->response);
	free(query);
}

static void query_destroy_pavl(void *query, void *dummy)
{
	confirm_query_destroy((struct confirm_query *)query);
}

static int query_cmp(const void *a, const void *b, void *dummy)
{
	const struct confirm_query *q1 = a;
	const struct confirm_query *q2 = b;
	if(q1->dst < q2->dst) { return -1; }
	if(q1->dst > q2->dst) { return +1; }
	if(q1->ttl < q2->ttl) { return -1; }
	if(q1->ttl > q2->ttl) { return +1; }
	if(q1->icmpid < q2->icmpid) { return -1; }
	if(q1->icmpid > q2->icmpid) { return +1; }
	if(q1->flowid < q2->flowid) { return -1; }
	if(q1->flowid > q2->flowid) { return +1; }
	/* removed this because setting the reverse flow ID does not work
	 * for 100% of routers (e.g., those that copy more than 8 bytes of
	 * the original IP payload */
	// if(q1->revflow < q2->revflow) { return -1; }
	// if(q1->revflow > q2->revflow) { return +1; }
	return 0;
} /* }}} */

/*****************************************************************************
 * data functions {{{
 ****************************************************************************/
#define DATA_FLAG_REVFLOW 0x8000
static uint16_t confirm_data_pack(uint8_t ttl, uint8_t fwflow, int fixrev)
{
	uint16_t retval = (fwflow << 8) + ttl;
	if(fixrev) retval |= DATA_FLAG_REVFLOW;
	return retval;
}
static void confirm_data_unpack(uint16_t data, uint8_t *ttl, uint8_t *fwflow,
		int *fixrev)
{
	*ttl = (uint8_t)(data & 0x00FF);
	*fwflow = (uint8_t)((data >> 8) & CONFIRM_MAX_FLOWID);
	*fixrev = data & DATA_FLAG_REVFLOW;
} /* }}} */
