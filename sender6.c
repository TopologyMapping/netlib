#include <stdlib.h>
#include <libnet.h>
#include <assert.h>
#include <limits.h>

#include "sender6.h"
#include "log.h"

#define SENDER_AUTO_CHECKSUM 0

/*****************************************************************************
 * static declarations
 ****************************************************************************/
struct sender6 {
	libnet_t *ln;
	struct libnet_in6_addr ip;
	libnet_ptag_t icmptag;
	libnet_ptag_t iptag;
	libnet_ptag_t tmptag;
	libnet_ptag_t tcptag;
	libnet_ptag_t opttag;
};

static uint16_t sender6_compute_icmp_payload(uint16_t icmpsum, uint16_t icmpid,
		uint16_t icmpseq);
static struct packet * sender6_make_packet(struct sender6 *s, int packet_type);
static uint16_t sender6_compute_tcp_sequence(uint8_t ttl, uint8_t fwflow,
		int fixrev);

/*****************************************************************************
 * public implementations
 ****************************************************************************/
struct sender6 * sender6_create(const char *device) /* {{{ */
{
	char errbuf[LIBNET_ERRBUF_SIZE];
	char *dev;
	struct sender6 *sender;

	dev = strdup(device);
	if(!dev) logea(__FILE__, __LINE__, NULL);
	sender = malloc(sizeof(struct sender6));
	if(!sender) logea(__FILE__, __LINE__, NULL);

	sender->ln = libnet_init(LIBNET_RAW6, dev, errbuf);
	if(!sender->ln) goto out_libnet;
	free(dev);
	sender->ip = libnet_get_ipaddr6(sender->ln);
	sender->icmptag = 0;
	sender->iptag = 0;
	sender->tmptag = 0;
	sender->tcptag = 0;
	sender->opttag = 0;

	logd(LOG_INFO, "%s dev=%s ok\n", __func__, device);

	return sender;

	out_libnet:
	loge(LOG_FATAL, __FILE__, __LINE__);
	logd(LOG_FATAL, "%s: %s", __func__, errbuf);
	free(sender);
	free(dev);
	return NULL;
} /* }}} */

void sender6_destroy(struct sender6 *sender) /* {{{ */
{
	logd(LOG_INFO, "%s ok\n", __func__);
	libnet_destroy(sender->ln);
	free(sender);
} /* }}} */

struct packet * sender6_send_icmp(struct sender6 *s, /* {{{ */
		struct libnet_in6_addr dst, uint8_t ttl,
		uint8_t traffic_class, uint32_t flow_label,
		uint16_t icmpsum, uint16_t icmpid, uint16_t icmpseq,
		size_t padding)
{
	padding += (padding % 2);
	size_t cnt = padding/sizeof(uint16_t) + 1;
	uint16_t *pload = malloc(cnt * sizeof(uint16_t));
	if(!pload) logea(__FILE__, __LINE__, NULL);
	memset(pload, 0, cnt * sizeof(uint16_t));

	pload[cnt-1] = sender6_compute_icmp_payload(icmpsum, icmpid, icmpseq);

	s->icmptag = libnet_build_icmpv6_echo(ICMP6_ECHO, 0,
		SENDER_AUTO_CHECKSUM, icmpid, icmpseq,
		(uint8_t *)pload, cnt * sizeof(uint16_t),
		s->ln, s->icmptag);

	free(pload);
	if(s->icmptag == -1) goto out;

	size_t sz = LIBNET_ICMPV6_ECHO_H + cnt*sizeof(uint16_t);
	s->iptag = libnet_build_ipv6(traffic_class, flow_label,
			sz, IPPROTO_ICMP6, ttl, s->ip, dst,
			NULL, 0,
			s->ln, s->iptag);

	if(s->iptag == -1) goto out;

	if(libnet_write(s->ln) < 0) goto out;

	struct packet *pkt = sender6_make_packet(s, 0);
	return pkt;

	out:
	loge(LOG_FATAL, __FILE__, __LINE__);
	logd(LOG_DEBUG, "%s %d %d error: %s\n", __func__, ttl, icmpsum,
			libnet_geterror(s->ln));
	libnet_clear_packet(s->ln);
	s->icmptag = 0;
	s->iptag = 0;
	return NULL;
} /* }}} */

/*****************************************************************************
 * static implementations
 ****************************************************************************/
static uint16_t sender6_compute_icmp_payload(uint16_t icmpsum, /*{{{*/
		uint16_t icmpid, uint16_t icmpseq)
{
	int payload;

	struct libnet_icmpv6_hdr hdrv6;
	hdrv6.icmp_type = ICMP6_ECHO;
	hdrv6.icmp_code = 0;
	hdrv6.icmp_sum = htons(icmpsum);
	hdrv6.id = htons(icmpid);
	hdrv6.seq = htons(icmpseq);
	payload = libnet_in_cksum((uint16_t *)&hdrv6, LIBNET_ICMPV6_ECHO_H);

	return (uint16_t)LIBNET_CKSUM_CARRY(payload);
} /*}}}*/

static struct packet * sender6_make_packet(struct sender6 *s, int packet_type)/*{{{*/
{
	libnet_t *ln = s->ln;
	uint8_t *ipbuf = libnet_getpbuf(ln, s->iptag);
	size_t iplen = libnet_getpbuf_size(ln, s->iptag);

	uint8_t *icbuf;
	size_t iclen;
	if(packet_type){
		// TCP
		icbuf = libnet_getpbuf(ln, s->tcptag);
		iclen = libnet_getpbuf_size(ln, s->tcptag);
	} else {
		// ICMP
		icbuf = libnet_getpbuf(ln, s->icmptag);
		iclen = libnet_getpbuf_size(ln, s->icmptag);
	}

	uint8_t *buf = malloc(iplen + iclen);
	if(!buf) logea(__FILE__, __LINE__, NULL);
	memcpy(buf, ipbuf, iplen);
	memcpy(buf+iplen, icbuf, iclen);
	struct packet *pkt = packet_create_ip(buf, iplen + iclen);
	free(buf);
	return pkt;
}/*}}}*/

// TODO (rafael): draft
static uint16_t sender6_compute_tcp_sequence(uint8_t ttl, uint8_t fwflow,
	int fixrev)
{
	uint16_t retval = (fwflow << 8) + ttl;
	if(fixrev) retval |= 0x8000;
	return retval;
}

// TODO (rafael): draft
struct packet * sender6_send_tcp(struct sender6 *s, struct libnet_in6_addr dst,
		uint8_t ttl, uint8_t traffic_class, uint32_t flow_label, uint8_t flowid,
		uint16_t sp, uint16_t dp)
{

	uint32_t seq = (0 << 16) | sender6_compute_tcp_sequence(ttl, flowid, 0);

	uint32_t ack = 0;
	uint8_t control = 0x002;
	uint16_t win = 5760;
	uint16_t sum = 0;
	uint16_t urg = 0;
	uint16_t h_len = LIBNET_TCP_H + 20;
	const uint8_t *payload = NULL;
	uint32_t payload_s = 0;

	// TODO (rafael): draft
	s->opttag = libnet_build_tcp_options((uint8_t*)"\003\003\002\004\002\001\002\004\001\011\000\000\000\000\000\000\000\000\000\000", 20, s->ln, s->opttag);

	if(s->opttag == -1) goto out;

	s->tcptag = libnet_build_tcp(sp, dp, seq, ack, control, win, sum, urg,
		h_len, payload, payload_s, s->ln, s->tcptag);

	if(s->tcptag == -1) goto out;

	size_t sz = LIBNET_TCP_H + 20;
	s->iptag = libnet_build_ipv6(traffic_class, flow_label, sz, 6, ttl, s->ip,
		dst, NULL, 0, s->ln, s->iptag);

	if(s->iptag == -1) goto out;

	if(libnet_write(s->ln) < 0) goto out;

	struct packet *pkt = sender6_make_packet(s, 1);
	return pkt;

	out:
	loge(LOG_FATAL, __FILE__, __LINE__);
	logd(LOG_DEBUG, "%s %d error: %s\n", __func__, ttl, libnet_geterror(s->ln));
	libnet_clear_packet(s->ln);
	s->tcptag = 0;
	s->iptag = 0;
	return NULL;
}
