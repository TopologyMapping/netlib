#include <stdlib.h>
#include <libnet.h>
#include <assert.h>

#include "sender4.h"
#include "log.h"

#define SENDER_TOS 0
#define SENDER_FRAG 0
#define SENDER_AUTO_CHECKSUM 0

/*****************************************************************************
 * static declarations
 ****************************************************************************/
struct sender4 {
	libnet_t *ln;
	uint32_t ip;
	libnet_ptag_t icmptag;
	libnet_ptag_t iptag;
};

static uint16_t sender4_compute_icmp_payload(uint16_t icmpsum,
		uint16_t icmpid, uint16_t icmpseq);
static struct packet * sender4_make_packet(struct sender4 *s);

/*****************************************************************************
 * public implementations
 ****************************************************************************/
struct sender4 * sender4_create(const char *device) /* {{{ */
{
	char errbuf[LIBNET_ERRBUF_SIZE];
	char *dev;
	struct sender4 *sender;

	dev = strdup(device);
	if(!dev) logea(__FILE__, __LINE__, NULL);
	sender = malloc(sizeof(*sender));
	if(!sender) logea(__FILE__, __LINE__, NULL);

	sender->ln = libnet_init(LIBNET_RAW4, dev, errbuf);
	if(!sender->ln) goto out_libnet;
	free(dev);

	sender->ip = libnet_get_ipaddr4(sender->ln);
	sender->icmptag = 0;
	sender->iptag = 0;

	logd(LOG_INFO, "%s dev=%s ok\n", __func__, device);
	return sender;

	out_libnet:
	loge(LOG_FATAL, __FILE__, __LINE__);
	logd(LOG_FATAL, "%s: %s", __func__, errbuf);
	free(sender);
	free(dev);
	return NULL;
} /* }}} */

void sender4_destroy(struct sender4 *sender) /* {{{ */
{
	logd(LOG_INFO, "%s ok\n", __func__);
	libnet_destroy(sender->ln);
	free(sender);
} /* }}} */

struct packet * sender4_send_icmp(struct sender4 *s, /* {{{ */
		uint32_t dst, uint8_t ttl, uint16_t ipid,
		uint16_t icmpsum, uint16_t icmpid, uint16_t icmpseq,
		size_t padding)
{
	padding += (padding % 2);
	size_t cnt = padding/sizeof(uint16_t) + 1;
	uint16_t *pload = malloc(cnt * sizeof(uint16_t));
	if(!pload) logea(__FILE__, __LINE__, NULL);
	memset(pload, 0, cnt * sizeof(uint16_t));

	pload[cnt-1] = sender4_compute_icmp_payload(icmpsum, icmpid, icmpseq);
	s->icmptag = libnet_build_icmpv4_echo(ICMP_ECHO, 0,
			SENDER_AUTO_CHECKSUM, icmpid, icmpseq,
			(uint8_t *)pload, cnt * sizeof(uint16_t),
			s->ln, s->icmptag);
	free(pload);
	if(s->icmptag == -1) goto out;

	size_t sz = LIBNET_IPV4_H+LIBNET_ICMPV4_ECHO_H + cnt*sizeof(uint16_t);
	s->iptag = libnet_build_ipv4(sz, SENDER_TOS, ipid, SENDER_FRAG,
			ttl, IPPROTO_ICMP, SENDER_AUTO_CHECKSUM,
			s->ip, dst, NULL, 0, s->ln, s->iptag);
	if(s->iptag == -1) goto out;

	if(libnet_write(s->ln) < 0) goto out;

	struct packet *pkt = sender4_make_packet(s);
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

struct packet * sender4_send_icmp_fixrev(struct sender4 *s, /* {{{ */
		uint32_t dst, uint8_t ttl, uint16_t ipid,
		uint16_t icmpsum, uint16_t rev_icmpsum, uint16_t icmpseq,
		size_t padding)
{
	struct libnet_icmpv4_hdr outer;
	outer.icmp_type = ICMP_TIMXCEED;
	outer.icmp_code = ICMP_TIMXCEED_INTRANS;
	outer.icmp_sum = htons(rev_icmpsum);
	outer.hun.gateway = 0;

	struct libnet_ipv4_hdr iip;
	iip.ip_hl = 5;
	iip.ip_v = 4;
	iip.ip_tos = SENDER_TOS;
	iip.ip_len = htons(LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + 2);
	iip.ip_id = htons(ipid);
	iip.ip_off = SENDER_FRAG;
	iip.ip_ttl = 1;
	iip.ip_p = IPPROTO_ICMP;
	iip.ip_sum = 0;
	iip.ip_src.s_addr = s->ip;
	iip.ip_dst.s_addr = dst;
	int chksum = libnet_in_cksum((uint16_t *)&iip, LIBNET_IPV4_H);
	iip.ip_sum = LIBNET_CKSUM_CARRY(chksum);

	struct libnet_icmpv4_hdr iicmp;
	iicmp.icmp_type = ICMP_ECHO;
	iicmp.icmp_code = 0;
	iicmp.icmp_sum = htons(icmpsum);
	iicmp.icmp_id = 0;
	iicmp.icmp_seq = htons(icmpseq);

	assert(LIBNET_ICMPV4_TIMXCEED_H == LIBNET_ICMPV4_ECHO_H);
	uint8_t buf[LIBNET_IPV4_H + 2*LIBNET_ICMPV4_ECHO_H];
	memcpy(buf, &outer, LIBNET_ICMPV4_ECHO_H);
	memcpy(buf + LIBNET_ICMPV4_ECHO_H, &iip, LIBNET_IPV4_H);
	memcpy(buf + LIBNET_ICMPV4_ECHO_H + LIBNET_IPV4_H, &iicmp,
			LIBNET_ICMPV4_ECHO_H);
	chksum = libnet_in_cksum((uint16_t *)buf, sizeof(buf));
	iicmp.icmp_id = LIBNET_CKSUM_CARRY(chksum);

	// logd(LOG_DEBUG, "IP chksum: 0x%04x\n", ntohs(iip.ip_sum));
	// logd(LOG_DEBUG, "ICMP chksum: 0x%04x\n", ntohs(iicmp.icmp_id));

	uint16_t icmpid = ntohs(iicmp.icmp_id);

	return sender4_send_icmp(s, dst, ttl, ipid,
			icmpsum, icmpid, icmpseq, padding);
} /* }}} */

/*****************************************************************************
 * static implementations
 ****************************************************************************/
static uint16_t sender4_compute_icmp_payload(uint16_t icmpsum, /*{{{*/
		uint16_t icmpid, uint16_t icmpseq)
{
	struct libnet_icmpv4_hdr hdr;
	hdr.icmp_type = ICMP_ECHO;
	hdr.icmp_code = 0;
	hdr.icmp_sum = htons(icmpsum);
	hdr.icmp_id = htons(icmpid);
	hdr.icmp_seq = htons(icmpseq);
	int payload = libnet_in_cksum((uint16_t *)&hdr, LIBNET_ICMPV4_ECHO_H);
	return (uint16_t)LIBNET_CKSUM_CARRY(payload);
} /*}}}*/

static struct packet * sender4_make_packet(struct sender4 *s)/*{{{*/
{
	libnet_t *ln = s->ln;
	uint8_t *ipbuf = libnet_getpbuf(ln, s->iptag);
	size_t iplen = libnet_getpbuf_size(ln, s->iptag);
	uint8_t *icbuf = libnet_getpbuf(ln, s->icmptag);
	size_t iclen = libnet_getpbuf_size(ln, s->icmptag);
	uint8_t *buf = malloc(iplen + iclen);
	if(!buf) logea(__FILE__, __LINE__, NULL);
	memcpy(buf, ipbuf, iplen);
	memcpy(buf+iplen, icbuf, iclen);
	struct packet *pkt = packet_create_ip(buf, iplen + iclen);
	free(buf);
	return pkt;
}/*}}}*/
