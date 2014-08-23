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

static uint16_t id2checksum[] = {
47485, 59641, 59636, 59814,
23611, 24011, 24763, 63590,
44783, 36350, 23048, 21862,
22390, 35853, 32285, 27013,
40630, 57726, 64680, 35276,
61823, 33612, 43377, 62109,
62647, 21362, 40351, 30905,
39930, 65105, 64025, 10451,
53500, 40931, 56155, 38023,
44366, 25553, 50878, 39562,
51740, 26910, 30285, 23196,
51888, 34531, 53831, 42176,
59203, 64103, 29638, 29803,
39094, 38088, 45801, 33501,
43723, 30103, 36960, 60135,
17854, 64411, 20306, 50570,
27569, 47643, 60544, 13979,
13830, 22346, 41505, 47566,
13688, 34730, 17193, 11123,
62243, 42876, 43048, 52564,
47583, 18453, 38243, 25176,
12635, 22307, 13967, 13919,
59912, 24539, 51469, 48554,
34217, 55905, 62396, 38044,
58741, 11926, 60163, 56968
};

/*****************************************************************************
 * declarations
 ****************************************************************************/
struct confirm {
	uint16_t icmpid;
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
static int confirm_recv_parse(const struct packet *pkt, uint32_t *dst,
	       uint8_t *ttl, uint8_t *flowid, uint32_t *ip, uint16_t icmpid);
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

static uint16_t confirm_data_pack(uint8_t ttl, uint8_t flowid);
static void confirm_data_unpack(uint16_t data, uint8_t *ttl, uint8_t *flowid);

/*****************************************************************************
 * public functions
 ****************************************************************************/
struct confirm * confirm_create(const char *device, uint16_t icmpid) /* {{{ */
{
	struct confirm *confirm;

	confirm = malloc(sizeof(struct confirm));
	if(!confirm) logea(__FILE__, __LINE__, NULL);
	confirm->icmpid = icmpid;

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
	uint8_t ttl, flowid;

	if(!confirm_recv_parse(pkt, &dst, &ttl, &flowid, &ip, conf->icmpid)) {
		return 1;
	}

	query = confirm_query_create(dst, ttl, flowid);
	query->ip = ip;
	query->answertime = pkt->tstamp;
	event = event_create(EVENT_ANSWER, query);

	confirm_sendevent(conf, event);
	return 0;
} /* }}} */

static int confirm_recv_parse(const struct packet *pkt, uint32_t *dst, /*{{{*/
	       uint8_t *ttl, uint8_t *flowid, uint32_t *ip, uint16_t icmpid)
{
	if(pkt->ip->ip_p != IPPROTO_ICMP) return 0;
	*ip = pkt->ip->ip_src.s_addr;

	if(pkt->icmp->icmp_type != ICMP_ECHOREPLY &&
			pkt->icmp->icmp_type != ICMP_TIMXCEED) {
		return 0;
	}

	uint16_t data;
	if(pkt->icmp->icmp_type == ICMP_ECHOREPLY) {
		*dst = pkt->ip->ip_src.s_addr;
		if(ntohs(pkt->icmp->icmp_id) != icmpid) return 0;
		data = ntohs(pkt->icmp->icmp_seq);
	} else if(pkt->icmp->icmp_type == ICMP_TIMXCEED) {
		struct libnet_ipv4_hdr *rip;
		struct libnet_icmpv4_hdr *ricmp;
		rip = (struct libnet_ipv4_hdr *)(pkt->payload);
		ricmp = (struct libnet_icmpv4_hdr *)(pkt->payload + rip->ip_hl*4);
		*dst = rip->ip_dst.s_addr;
		if(pkt->icmp->icmp_code != ICMP_TIMXCEED_INTRANS) return 0;
		if(ntohs(ricmp->icmp_id) != icmpid) return 0;
		data = ntohs(ricmp->icmp_seq);
	}
	confirm_data_unpack(data, ttl, flowid);
	return 1;
} /* }}} */

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
	uint16_t data;
	struct confirm_query *query = ev->query;
	uint16_t checksum = id2checksum[query->flowid];
	assert(ev->type == EVENT_SENDPACKET);

	data = confirm_data_pack(query->ttl, query->flowid);

	sender_send_icmp(conf->sender, query->dst, query->ttl, 1,
		checksum, conf->icmpid, data, 0);

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
	timespec_logd(60, aux);
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
	confirm_query_destroy(ev->query);
	pavl_assert_delete(conf->queries, query);
	pavl_assert_delete(conf->events, query->event);
	event_destroy(query->event);
	query->cb(query);
	return;

	out_spurious:
	inet_ntop(AF_INET, &(ev->query->dst), dump, INET_ADDRSTRLEN);
	logd(5, "%s no query for dst=%s ttl=%d flow=%d\n", __func__,
			dump, ev->query->ttl, ev->query->flowid);
	out:
	confirm_query_destroy(ev->query);
} /* }}} */

/*****************************************************************************
 * query functions {{{
 ****************************************************************************/
struct confirm_query *
confirm_query_create(uint32_t dst, uint8_t ttl, uint8_t flowid)
{
	struct confirm_query *query;

	query = malloc(sizeof(struct confirm_query));
	if(!query) logea(__FILE__, __LINE__, NULL);
	memset(query, 0, sizeof(struct confirm_query));
	query->ntries = 1;
	query->dst = dst;
	query->ttl = ttl;
	query->flowid = flowid;
	query->ip = UINT_MAX;
	query->probetime.tv_sec = 1;
	query->timeout.tv_sec = 3;
	return query;
}

void confirm_query_destroy(struct confirm_query *query)
{
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
	if(q1->flowid < q2->flowid) { return -1; }
	if(q1->flowid > q2->flowid) { return +1; }
	return 0;
} /* }}} */

/*****************************************************************************
 * data functions {{{
 ****************************************************************************/
static uint16_t confirm_data_pack(uint8_t ttl, uint8_t flowid)
{
	uint16_t retval = (ttl << 8) + flowid;
	return retval;
}
static void confirm_data_unpack(uint16_t data, uint8_t *ttl, uint8_t *flowid)
{
	*ttl = (uint8_t)((data & 0xFF00) >> 8);
	*flowid = (uint8_t)(data & 0xFF);
} /* }}} */
