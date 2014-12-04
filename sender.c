#include <stdlib.h>
#include <libnet.h>
#include <assert.h>

#include "sender.h"
#include "log.h"

#define SENDER_TOS 0
#define SENDER_FRAG 0
#define SENDER_AUTO_CHECKSUM 0

/*****************************************************************************
 * static declarations
 ****************************************************************************/
struct sender {
	libnet_t *ln;
	struct sockaddr *ip;
	libnet_ptag_t icmptag;
	libnet_ptag_t iptag;
	libnet_ptag_t tmptag;
};

static uint16_t sender_compute_icmp_payload(uint16_t icmpsum, uint16_t icmpid,
		uint16_t icmpseq, uint8_t ipversion);
static struct packet * sender_make_packet(struct sender *s);

/*****************************************************************************
 * public implementations
 ****************************************************************************/
struct sender * sender_create(const char *device, int ipversion) /* {{{ */
{
	char errbuf[LIBNET_ERRBUF_SIZE];
	char *dev;
	struct sender *sender;

	dev = strdup(device);
	if(!dev) logea(__FILE__, __LINE__, NULL);
	sender = malloc(sizeof(struct sender));
	if(!sender) logea(__FILE__, __LINE__, NULL);

	if (ipversion == 4){
        sender->ln = libnet_init(LIBNET_RAW4, dev, errbuf);
        if(!sender->ln) goto out_libnet;
        free(dev);

        struct sockaddr_in *ipv4 = malloc(sizeof(struct sockaddr_in));
        ipv4->sin_family = AF_INET;
        ipv4->sin_addr.s_addr = libnet_get_ipaddr4(sender->ln);
        sender->ip = ipv4;
	}
	else if (ipversion == 6){
        sender->ln = libnet_init(LIBNET_RAW6, dev, errbuf);
    	if(!sender->ln) goto out_libnet;
        free(dev);
        struct libnet_in6_addr *ipv6 = malloc(sizeof(struct libnet_in6_addr));
        *ipv6 = libnet_get_ipaddr6(sender->ln);
        sender->ip = ipv6;
	}

	sender->icmptag = 0;
	sender->iptag = 0;
	sender->tmptag = 0;

	logd(LOG_INFO, "%s dev=%s ok\n", __func__, device);

	return sender;

	out_libnet:
	loge(LOG_FATAL, __FILE__, __LINE__);
	logd(LOG_FATAL, "%s: %s", __func__, errbuf);
	free(sender);
	free(dev);
	return NULL;
} /* }}} */

void sender_destroy(struct sender *sender) /* {{{ */
{
	logd(LOG_INFO, "%s ok\n", __func__);
	libnet_destroy(sender->ln);
	free(sender);
} /* }}} */

struct packet * sender_send_icmp(struct sender *s, /* {{{ */
		struct sockaddr *dst, uint8_t ttl, uint16_t ipid,
		uint16_t icmpsum, uint16_t icmpid, uint16_t icmpseq,
		size_t padding)
{
	if((padding % 2) == 1) padding++;
	size_t cnt = padding/sizeof(uint16_t) + 1;
	uint16_t *pload = malloc(cnt * sizeof(uint16_t));
	if(!pload) logea(__FILE__, __LINE__, NULL);
	memset(pload, 0, cnt * sizeof(uint16_t));

	if(s->ip->sa_family == AF_INET){
        pload[cnt-1] = sender_compute_icmp_payload(icmpsum, icmpid, icmpseq, 4);
        s->icmptag = libnet_build_icmpv4_echo(ICMP_ECHO, 0,
            SENDER_AUTO_CHECKSUM, icmpid, icmpseq,
            // (uint8_t *)(&payload), sizeof(uint16_t),
            (uint8_t *)pload, cnt * sizeof(uint16_t),
            s->ln, s->icmptag);
        free(pload);
        if(s->icmptag == -1) goto out;

        size_t sz = LIBNET_IPV4_H+LIBNET_ICMPV4_ECHO_H + cnt*sizeof(uint16_t);
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)s->ip;
        struct sockaddr_in *ipv4_dst = (struct sockaddr_in *)dst;
        s->iptag = libnet_build_ipv4(sz, SENDER_TOS, ipid, SENDER_FRAG,
                ttl, IPPROTO_ICMP, SENDER_AUTO_CHECKSUM,
                ipv4->sin_addr.s_addr, ipv4_dst->sin_addr.s_addr, NULL, 0, s->ln, s->iptag);
        if(s->iptag == -1) goto out;

        if(libnet_write(s->ln) < 0) goto out;
	}
	else{
        pload[cnt-1] = sender_compute_icmp_payload(icmpsum, icmpid, icmpseq, 6);
        s->icmptag = libnet_build_icmpv6_echo(ICMP6_ECHO, 0,
            SENDER_AUTO_CHECKSUM, icmpid, icmpseq,
            // (uint8_t *)(&payload), sizeof(uint16_t),
            (uint8_t *)pload, cnt * sizeof(uint16_t),
            s->ln, s->icmptag);
        free(pload);
        if(s->icmptag == -1) goto out;

        size_t sz = LIBNET_IPV6_H+LIBNET_ICMPV6_ECHO_H + cnt*sizeof(uint16_t);
        struct libnet_in6_addr *ipv6 = (struct libnet_in6_addr *)s->ip;
        struct libnet_in6_addr *ipv6_dst = (struct libnet_in6_addr *)dst;
        s->iptag = libnet_build_ipv6(0, 0, sz, 0, ttl, *ipv6, *ipv6_dst,  NULL, 0, s->ln, s->iptag);
        if(s->iptag == -1) goto out;
	}

	struct packet *pkt = sender_make_packet(s);
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

struct packet * sender_send_icmp_fixrev(struct sender *s, /* {{{ */
		uint32_t dst, uint8_t ttl, uint16_t ipid,
		uint16_t icmpsum, uint16_t rev_icmpsum, uint16_t icmpseq,
		size_t padding)
{
	uint16_t icmpid;

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

    icmpid = ntohs(iicmp.icmp_id);

    return sender_send_icmp(s, dst, ttl, ipid, icmpsum, icmpid, icmpseq, padding);
} /* }}} */

/*****************************************************************************
 * static implementations
 ****************************************************************************/
static uint16_t sender_compute_icmp_payload(uint16_t icmpsum, /*{{{*/
		uint16_t icmpid, uint16_t icmpseq, uint8_t ipversion)
{
	int payload;
	if (ipversion == 4){
        struct libnet_icmpv4_hdr hdr;
        hdr.icmp_type = ICMP_ECHO;
        hdr.icmp_code = 0;
        hdr.icmp_sum = htons(icmpsum);
        hdr.icmp_id = htons(icmpid);
        hdr.icmp_seq = htons(icmpseq);
        payload = libnet_in_cksum((uint16_t *)&hdr, LIBNET_ICMPV4_ECHO_H);
	}
    else if (ipversion == 6){
        struct libnet_icmpv6_hdr hdrv6;
        hdrv6.icmp_type = ICMP6_ECHO;
        hdrv6.icmp_code = 0;
        hdrv6.icmp_sum = htons(icmpsum);
        hdrv6.id = htons(icmpid);
        hdrv6.seq = htons(icmpseq);
        payload = libnet_in_cksum((uint16_t *)&hdrv6, LIBNET_ICMPV6_ECHO_H);
    }
	return (uint16_t)LIBNET_CKSUM_CARRY(payload);
} /*}}}*/

static struct packet * sender_make_packet(struct sender *s)/*{{{*/
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


struct libnet_in6_addr nameToAddr6WithSender (struct sender *s, char* dst){
     struct libnet_in6_addr dst_ipv6;
     dst_ipv6 = libnet_name2addr6(s->ln, dst , LIBNET_DONT_RESOLVE);
     return dst_ipv6;
}
