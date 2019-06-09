#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <assert.h>

#include <sys/types.h>
#include <arpa/inet.h>

#include <libnet.h>
#include <limits.h>
#include "demux.h"
#include "sender4.h"
#include "sender6.h"
#include "packet.h"
#include "confirm.h"

#include "dstructs/dlist.h"
#include "dstructs/pavl.h"
#include "dstructs/timespec.h"
#include "log/log.h"

#define PROBE_TYPE_ICMP 1
#define PROBE_TYPE_TCP 2

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
	struct sender4 *sender4;
	struct sender6 *sender6;
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

static struct confirm_query * confirm_pkt_parse4(const struct packet *pkt);
static struct confirm_query * confirm_pkt_parse6(const struct packet *pkt);
static struct confirm_query * confirm_pkt_parse(const struct packet *pkt);

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

	confirm = malloc(sizeof(*confirm));
	if(!confirm) logea(__FILE__, __LINE__, NULL);

	confirm->events = pavl_create(event_cmp, NULL, NULL);
	if(!confirm->events) goto out;
	confirm->queries = pavl_create(query_cmp, NULL, NULL);
	if(!confirm->queries) goto out_events;

	pthread_mutex_init(&confirm->evlist_mut, NULL);
	pthread_cond_init(&confirm->event_cond, NULL);

	confirm->evlist = dlist_create();
	if(!confirm->evlist) goto out_cond;

	confirm->sender4 = sender4_create(device);
	if(!confirm->sender4) goto out_evlist;
	confirm->sender6 = sender6_create(device);
	if(!confirm->sender6) goto out_sender4;
	if(pthread_create(&confirm->thread, NULL, confirm_thread, confirm)) {
		goto out_sender6;
	}

	demux_listener_add(confirm_recv, confirm);

	logd(LOG_INFO, "%s dev=%s ok\n", __func__, device);
	return confirm;

	out_sender6:
	loge(LOG_DEBUG, __FILE__, __LINE__);
	sender6_destroy(confirm->sender6);
	out_sender4:
	loge(LOG_DEBUG, __FILE__, __LINE__);
	sender4_destroy(confirm->sender4);
	out_evlist:
	loge(LOG_DEBUG, __FILE__, __LINE__);
	dlist_destroy(confirm->evlist, NULL);
	out_cond:
	loge(LOG_DEBUG, __FILE__, __LINE__);
	pavl_destroy(confirm->queries, NULL);
	pthread_mutex_destroy(&confirm->evlist_mut);
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
	sender6_destroy(confirm->sender6);
	sender4_destroy(confirm->sender4);
	pavl_destroy(confirm->events, event_destroy_pavl);
	pavl_destroy(confirm->queries, query_destroy_pavl);
	free(confirm);
} /* }}} */

void confirm_submit(struct confirm *confirm, struct confirm_query *query)/*{{{*/
{
	struct event *ev = event_create(EVENT_QUERY, query);
	if(!ev) return;
	confirm_sendevent(confirm, ev);
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

static void confirm_sendevent(struct confirm *confirm, struct event *ev)/*{{{*/
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

	query = confirm_pkt_parse(pkt);
	if(query == NULL) return 1;

	query->response = packet_clone(pkt);
	query->answertime = pkt->tstamp;
	event = event_create(EVENT_ANSWER, query);

	confirm_sendevent(conf, event);
	return 0;
} /* }}} */

static struct confirm_query * confirm_pkt_parse(const struct packet *pkt)/*{{{*/
{
	if(pkt->ipversion == 4) return confirm_pkt_parse4(pkt);
	if(pkt->ipversion == 6) return confirm_pkt_parse6(pkt);
	logd(LOG_FATAL, "%s: unknown addr family\n", __func__);
	return NULL;
} /*}}}*/

static struct confirm_query * confirm_pkt_parse4(const struct packet *pkt)/*{{{*/
{
	assert(pkt->ip->ip_v == 4);
	if(pkt->ip->ip_p != IPPROTO_ICMP) return NULL;
	if(pkt->icmp->icmp_type != ICMP_ECHOREPLY &&
			pkt->icmp->icmp_type != ICMP_TIMXCEED) {
		return NULL;
	}

	uint16_t ipid = 0;
	uint16_t icmpid = 0;
	uint16_t revsum = 0;
	uint16_t data = 0;

	struct sockaddr_in src;
	struct sockaddr_in dst;
	src.sin_family = AF_INET;
	dst.sin_family = AF_INET;
	if(pkt->icmp->icmp_type == ICMP_ECHOREPLY) {
		src.sin_addr.s_addr = pkt->ip->ip_dst.s_addr;
		dst.sin_addr.s_addr = pkt->ip->ip_src.s_addr;
		icmpid = ntohs(pkt->icmp->icmp_id);
		data = ntohs(pkt->icmp->icmp_seq);
	} else if(pkt->icmp->icmp_type == ICMP_TIMXCEED) {
		if(pkt->icmp->icmp_code != ICMP_TIMXCEED_INTRANS) return NULL;
		struct libnet_ipv4_hdr *rip;
		struct libnet_icmpv4_hdr *ricmp;
		rip = (struct libnet_ipv4_hdr *)(pkt->payload);
		ricmp = (struct libnet_icmpv4_hdr *)(pkt->payload + rip->ip_hl*4);
		src.sin_addr.s_addr = rip->ip_src.s_addr;
		dst.sin_addr.s_addr = rip->ip_dst.s_addr;
		ipid = ntohs(rip->ip_id);
		icmpid = ntohs(ricmp->icmp_id);
		revsum = ntohs(pkt->icmp->icmp_sum);
		data = ntohs(ricmp->icmp_seq);
	}

	uint8_t ttl;
	uint8_t flowid;
	uint8_t revflow = 0;
	int fixrev;
	confirm_data_unpack(data, &ttl, &flowid, &fixrev);
	if(fixrev) {
		revflow = confirm_inverse_flowid(revsum);
		icmpid = 0;
	}

	struct sockaddr_storage *srcptr = (struct sockaddr_storage *)&src;
	struct sockaddr_storage *dstptr = (struct sockaddr_storage *)&dst;
	struct confirm_query *q = confirm_query_create4(srcptr, dstptr,
			ttl, ipid,
			icmpid, flowid, revflow, NULL);
	struct sockaddr_in *saddr = (struct sockaddr_in *)&(q->ip);
	saddr->sin_family = AF_INET;
	saddr->sin_addr.s_addr = pkt->ip->ip_src.s_addr;
	return q;
} /*}}}*/

static struct confirm_query * confirm_pkt_parse6(const struct packet *pkt)/*{{{*/
{
	assert(pkt->ip->ip_v == 6);

	uint16_t icmpid = 0;
	uint16_t data = 0;
	uint8_t traffic_class = 0;
	uint32_t flow_label = 0;
	int probe_type = 0;

	struct sockaddr_in6 src;
	struct sockaddr_in6 dst;
	src.sin6_family = AF_INET6;
	dst.sin6_family = AF_INET6;

	if((pkt->ipv6->ip_nh == IPPROTO_TCP) && (pkt->tcp->th_flags & TH_ACK)) {
		// TCP ACK
		probe_type = PROBE_TYPE_TCP;
		memcpy(&src.sin6_addr, &pkt->ipv6->ip_dst, sizeof(src.sin6_addr));
		memcpy(&dst.sin6_addr, &pkt->ipv6->ip_src, sizeof(dst.sin6_addr));
		// syn-ack holds syn tcp sequence number plus 1
		uint32_t tcp_sequence_number = ntohl(pkt->tcp->th_ack) - 1;
		data = (uint16_t) (tcp_sequence_number & 0x0000FFFF);
	} else if(pkt->ipv6->ip_nh == IPPROTO_ICMP6) {
		if(pkt->icmpv6->icmp_type == ICMP6_ECHOREPLY) {
			probe_type = PROBE_TYPE_ICMP;
			memcpy(&src.sin6_addr, &pkt->ipv6->ip_dst, sizeof(src.sin6_addr));
			memcpy(&dst.sin6_addr, &pkt->ipv6->ip_src, sizeof(dst.sin6_addr));
			icmpid = ntohs(pkt->icmpv6->id);
			data = ntohs(pkt->icmpv6->seq);
		} else if((pkt->icmpv6->icmp_type == ICMP6_TIMXCEED) &&
                (pkt->icmpv6->icmp_code == ICMP_TIMXCEED_INTRANS)) {
			struct libnet_ipv6_hdr *rip;
			struct libnet_icmpv6_hdr *ricmp;
            struct libnet_tcp_hdr *rtcp;
			rip = (struct libnet_ipv6_hdr *)(pkt->payload);

            if(rip->ip_nh == IPPROTO_ICMP6) {
                probe_type = PROBE_TYPE_ICMP;
                ricmp = (struct libnet_icmpv6_hdr *)
                        (pkt->payload + LIBNET_IPV6_H);
				memcpy(&src.sin6_addr, &rip->ip_src, sizeof(src.sin6_addr));
    			memcpy(&dst.sin6_addr, &rip->ip_dst, sizeof(dst.sin6_addr));
    			uint32_t flags = *(uint32_t *)(rip->ip_flags);
    			traffic_class = (flags & 0x0FF00000) >> 20;
    			flow_label = (flags & 0x000FFFFF);
    			icmpid = ntohs(ricmp->id);
    			data = ntohs(ricmp->seq);
            } else if(rip->ip_nh == IPPROTO_TCP) {
                probe_type = PROBE_TYPE_TCP;
                rtcp = (struct libnet_tcp_hdr *)(pkt->payload + LIBNET_IPV6_H);
				memcpy(&src.sin6_addr, &rip->ip_src, sizeof(src.sin6_addr));
    			memcpy(&dst.sin6_addr, &rip->ip_dst, sizeof(dst.sin6_addr));
    			uint32_t flags = *(uint32_t *)(rip->ip_flags);
    			traffic_class = (flags & 0x0FF00000) >> 20;
    			flow_label = (flags & 0x000FFFFF);
    			data = (uint16_t) (ntohl(rtcp->th_seq) & 0x0000FFFF);
            } else {
                return NULL; // no ICMP or TCP encapsulated
            }
		} else if((pkt->icmpv6->icmp_type == ICMP6_DST_UNREACH) &&
				(pkt->icmpv6->icmp_code == ICMP6_DST_UNREACH_NOPORT)){
			// Port unreachable
			struct libnet_ipv6_hdr *rip;
			struct libnet_tcp_hdr *rtcp;
			probe_type = PROBE_TYPE_TCP;
			rip = (struct libnet_ipv6_hdr *)(pkt->payload);
			rtcp = (struct libnet_tcp_hdr *)(pkt->payload + LIBNET_IPV6_H);
			memcpy(&src.sin6_addr, &rip->ip_src, sizeof(src.sin6_addr));
			memcpy(&dst.sin6_addr, &rip->ip_dst, sizeof(dst.sin6_addr));
			uint32_t flags = *(uint32_t *)(rip->ip_flags);
			traffic_class = (flags & 0x0FF00000) >> 20;
			flow_label = (flags & 0x000FFFFF);
			data = (uint16_t)(ntohl(rtcp->th_seq) & 0x0000FFFF);
		} else {
			return NULL; // unsupported ICMP type
		}

	} else {
		return NULL; // no TCP or ICMP
	}

	uint8_t ttl;
	uint8_t flowid;
	int fixrev;
	confirm_data_unpack(data, &ttl, &flowid, &fixrev);
	assert(fixrev == 0);

	struct sockaddr_storage *srcptr = (struct sockaddr_storage *)&src;
	struct sockaddr_storage *dstptr = (struct sockaddr_storage *)&dst;
	if(probe_type == PROBE_TYPE_ICMP) {
		struct confirm_query *q = confirm_query_create6(srcptr, dstptr,
				ttl, traffic_class, flow_label,
				icmpid, flowid, NULL);
	} else if(probe_type == PROBE_TYPE_TCP) {
		// These fields are not used in match, initialize with zero:
		uint16_t src_port = 0;
		uint16_t dst_port = 0;
		uint32_t ack_number = 0;
		uint8_t control_flags = 0;
		uint32_t window = 0;
		uint16_t urgent_pointer = 0;
		q = confirm_query_create6_tcp(srcptr, dstptr, ttl,
			traffic_class, flow_label,
			flowid, src_port, dst_port, ack_number, control_flags, window,
			urgent_pointer, NULL);
	} else {
		logd(LOG_FATAL, "%s %d: unexpected probe type\n", __FILE__, __LINE__);
		return NULL;
	}

	struct sockaddr_in6 *ip = (struct sockaddr_in6 *)&(q->ip);
	ip->sin6_family = AF_INET6;
	memcpy(&(ip->sin6_addr), &(pkt->ipv6->ip_src), sizeof(ip->sin6_addr));
	return q;
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
	char *addr = sockaddr_tostr(&(query->dst));
	if(!addr) logea(__FILE__, __LINE__, NULL);
	logd(LOG_EXTRA, "query dst=%s ttl=%d flowid=%d\n", addr, query->ttl,
			query->flowid);
	free(addr);
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
	if (query->probe_type == PROBE_TYPE_TCP) {
		struct sockaddr_in6 *dst = (struct sockaddr_in6 *) &(query->dst);
		struct libnet_in6_addr ipv6_dst;
		memcpy(&ipv6_dst, &(dst->sin6_addr), sizeof(ipv6_dst));

		data = confirm_data_pack(query->ttl, query->flowid, 0);
		uint32_t seq_number = data;

		pkt = sender6_send_tcp(conf->sender6, ipv6_dst, query->ttl,
			query->traffic_class, query->flow_label, query->tcp.src_port,
			query->tcp.dst_port, seq_number, query->tcp.ack_number,
			query->tcp.control_flags, query->tcp.window, query->tcp.urgent_pointer);

	} else if (query->probe_type == PROBE_TYPE_ICMP) {
		if(query->icmpid) { /* if icmpid == 0 then we fix the reverse flowid */
			data = confirm_data_pack(query->ttl, query->flowid, 0);
			if(query->dst.ss_family == AF_INET) {
				struct sockaddr_in *src_sa;
				struct sockaddr_in *dst_sa;
				src_sa = (struct sockaddr_in *)(&(query->src));
				dst_sa = (struct sockaddr_in *)(&(query->dst));
				pkt = sender4_send_icmp(conf->sender4,
						src_sa->sin_addr.s_addr,
						dst_sa->sin_addr.s_addr,
						query->ttl,
						query->ipid,
						id2checksum[query->flowid],
						query->icmpid, data,
						query->padding);
			} else {
				struct sockaddr_in6 *sin6;
				sin6 = (struct sockaddr_in6 *)(&(query->src));
				struct sockaddr_in6 *din6;
				din6  = (struct sockaddr_in6 *)(&(query->dst));
				struct libnet_in6_addr ipv6_src;
				struct libnet_in6_addr ipv6_dst;
				memcpy(&ipv6_src, &(sin6->sin6_addr), sizeof(ipv6_src));
				memcpy(&ipv6_dst, &(din6->sin6_addr), sizeof(ipv6_dst));
				pkt = sender6_send_icmp(conf->sender6,
						ipv6_src,
						ipv6_src,
						query->ttl,
						query->traffic_class, query->flow_label,
						id2checksum[query->flowid],
						query->icmpid, data,
						query->padding);
			}
		} else {
			data = confirm_data_pack(query->ttl, query->flowid, 1);
			uint16_t revsum = id2checksum[query->revflow];
			if(query->ip.ss_family == AF_INET){
				struct sockaddr_in *src_sa;
				struct sockaddr_in *dst_sa;
				src_sa = (struct sockaddr_in *)(&(query->src));
				dst_sa = (struct sockaddr_in *)(&(query->dst));
				pkt = sender4_send_icmp_fixrev(conf->sender4,
						src_sa->sin_addr.s_addr,
						dst_sa->sin_addr.s_addr,
						query->ttl,
						query->ipid,
						id2checksum[query->flowid],
						revsum, data,
						query->padding);
			}
			else {
				logd(LOG_FATAL, "%s %d: fixrev for IPv6 not impl\n",
						__FILE__, __LINE__);
				pkt = NULL;
			}
		}
	}

	if(query->probe == NULL) {
		query->probe = pkt;
	}
	else {
		packet_destroy(pkt);
	}
	query->trynum++;
	query->lastpkt = ev->time;
	event_run_schednext(conf, query);
}

static void event_run_timeout(struct confirm *conf, struct event *ev)
{
	struct confirm_query *query = ev->query;
	assert(query->trynum == query->ntries);
	pavl_assert_delete(conf->queries, query);
	assert(query->ip.ss_family == query->dst.ss_family);
	/* query->ip.sinX_addr was initialized with all bits set */
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

	char *addr;
	out_spurious:
	addr = sockaddr_tostr(&(query->dst));
	logd(5, "%s no query for dst=%s ttl=%d flowid=%d revflow=%d\n",
			__func__, addr,
			ev->query->ttl, ev->query->flowid,
			ev->query->revflow);
	free(addr);
	out:
	confirm_query_destroy(ev->query);
} /* }}} */

/*****************************************************************************
 * query functions {{{
 ****************************************************************************/
struct confirm_query *confirm_query_create_defaults(
		const struct sockaddr_storage *src,
		const struct sockaddr_storage *dst,
		uint8_t ttl, uint8_t flowid,
		confirm_query_cb cb)
{
	struct confirm_query *query;
	query = malloc(sizeof(*query));
	if(!query) logea(__FILE__, __LINE__, NULL);

	memcpy(&(query->src), src, sizeof(query->src));
	memcpy(&(query->dst), dst, sizeof(query->dst));
	memset(&(query->ip), UINT8_MAX, sizeof(query->ip));
	query->ip.ss_family = dst->ss_family;

	if(flowid > CONFIRM_MAX_FLOWID) {
		logd(LOG_WARN, "%s,%d: flowid > CONFIRM_MAX_FLOWID (%d)!\n", __FILE__,
			__LINE__, CONFIRM_MAX_FLOWID);
	}

	query->flowid = flowid & CONFIRM_MAX_FLOWID;
	query->ttl = ttl;
	query->padding = 0;
	query->revflow = 0;
	query->ntries = 3;
	query->cb = cb;
	query->data = NULL;
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

struct confirm_query *
confirm_query_create4(
		const struct sockaddr_storage *src,
		const struct sockaddr_storage *dst,
		uint8_t ttl, uint16_t ipid,
		uint16_t icmpid, uint8_t flowid, uint8_t revflow,
		confirm_query_cb cb)
{
	if(revflow > CONFIRM_MAX_FLOWID) {
		logd(LOG_WARN, "%s,%d: revflow > CONFIRM_MAX_FLOWID (%d)!\n", __FILE__,
			__LINE__, CONFIRM_MAX_FLOWID);
	}

	struct confirm_query *query = confirm_query_create_defaults(
			src, dst, ttl, flowid, cb);
	query->ipid = ipid;
	query->icmpid = icmpid;
	query->revflow = (icmpid) ? 0 : revflow & CONFIRM_MAX_FLOWID;
	// Just in case (for IPv4 we only support ICMP)
	query->probe_type = PROBE_TYPE_ICMP;
	return query;
}

struct confirm_query *
confirm_query_create6_icmp(
		const struct sockaddr_storage *src,
		const struct sockaddr_storage *dst,
		uint8_t ttl,
		uint8_t traffic_class, uint32_t flow_label,
		uint16_t icmpid, uint8_t flowid,
		confirm_query_cb cb)
{
	struct confirm_query *query;
	query = confirm_query_create_defaults(src, dst, ttl, flowid, cb);
	query->traffic_class = traffic_class;
	query->flow_label = flow_label;
	query->icmpid = icmpid;
	query->probe_type = PROBE_TYPE_ICMP;
	return query;
}

struct confirm_query *
confirm_query_create6_tcp(
		const struct sockaddr_storage *src,
		const struct sockaddr_storage *dst,
		uint8_t ttl, uint8_t traffic_class, uint32_t flow_label, uint8_t flowid,
		uint16_t src_port, uint16_t dst_port, uint32_t ack_number,
		uint8_t control_flags, uint16_t window, uint16_t urgent_pointer,
		confirm_query_cb cb)
{
	struct confirm_query *query;
	query = confirm_query_create_defaults(src, dst, ttl, flowid, cb);
	query->traffic_class = traffic_class;
	query->flow_label = flow_label;
	query->tcp.src_port = src_port;
	query->tcp.dst_port = dst_port;
	query->tcp.ack_number = ack_number;
	query->tcp.control_flags = control_flags;
	query->tcp.window = window;
	query->tcp.urgent_pointer = urgent_pointer;
	query->probe_type = PROBE_TYPE_TCP;
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

	int cmp = sockaddr_cmp(&(q1->dst), &(q2->dst), dummy);
	if(cmp) return cmp;
	if(q1->ttl < q2->ttl) { return -1; }
	if(q1->ttl > q2->ttl) { return +1; }
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
