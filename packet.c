#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "packet.h"
#include "log.h"

static struct packet * packet_create(const uint8_t *buf, size_t buflen);
static void packet_fill(struct packet *pkt, size_t ipoffset);

struct packet * packet_create_eth(const uint8_t *ethbuf, size_t buflen)/*{{{*/
{
	struct packet *pkt = packet_create(ethbuf, buflen);
	packet_fill(pkt, LIBNET_ETH_H);
	return pkt;
}/*}}}*/

struct packet * packet_create_ip(const uint8_t *ipbuf, size_t buflen)/*{{{*/
{
	struct packet *pkt = packet_create(ipbuf, buflen);
	packet_fill(pkt, 0);
	return pkt;
}/*}}}*/

struct packet * packet_clone(const struct packet *orig)/*{{{*/
{
	struct packet *pkt = packet_create(orig->buf, orig->buflen);
	pkt->tstamp = orig->tstamp;
	pkt->ip = orig->ip;
	pkt->icmp = orig->icmp;
	pkt->payload = orig->payload;
	return pkt;
}/*}}}*/

void packet_destroy(struct packet *pkt)/*{{{*/
{
	free(pkt->buf);
	free(pkt);
}/*}}}*/

char * packet_tostr(const struct packet *pkt)/*{{{*/
{
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(pkt->ip->ip_src), src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(pkt->ip->ip_dst), dst, INET_ADDRSTRLEN);

	char buf1[4096];
	sprintf(buf1, 	"IP hdrlen %d tos 0x%x len %d\n"
			"IP id %d frag 0x%x\n"
			"IP ttl %d proto %d chksum 0x%x\n"
			"IP src %s 0x%x\n"
			"IP dst %s 0x%x\n",
			(int)pkt->ip->ip_hl * 4,
			(int)pkt->ip->ip_tos,
			(int)ntohs(pkt->ip->ip_len),
			(int)ntohs(pkt->ip->ip_id),
			(int)pkt->ip->ip_off,
			(int)pkt->ip->ip_ttl,
			(int)pkt->ip->ip_p,
			(int)ntohs(pkt->ip->ip_sum),
			src, (int)pkt->ip->ip_src.s_addr,
			dst, (int)pkt->ip->ip_dst.s_addr);

	uint8_t proto = pkt->ip->ip_p;
	char buf2[4096];
	char buf3[4096];
	switch(proto) {
	case IPPROTO_ICMP:
		sprintf(buf2, 	"ICMP type %d code %d chksum 0x%x",
				pkt->icmp->icmp_type,
				pkt->icmp->icmp_code,
				ntohs(pkt->icmp->icmp_sum));
		uint8_t type = pkt->icmp->icmp_type;
		if(type == ICMP_ECHOREPLY || type == ICMP_ECHO) {
			sprintf(buf3,	"\nICMP id %d seq %d",
					ntohs(pkt->icmp->icmp_id),
					ntohs(pkt->icmp->icmp_seq));
		}
		strcat(buf2, buf3);
		break;
	default:
		sprintf(buf2, "transport protocol not supported");
		break;
	}

	strcat(buf1, buf2);

	char *ret = strdup(buf1);
	if(!ret) logea(__FILE__, __LINE__, NULL);
	return ret;
}/*}}}*/



static struct packet * packet_create(const uint8_t *buf, size_t buflen)/*{{{*/
{
	struct packet *pkt = malloc(sizeof(*pkt));
	if(!pkt) logea(__FILE__, __LINE__, NULL);
	pkt->buf = malloc(buflen);
	if(!pkt->buf) logea(__FILE__, __LINE__, NULL);
	pkt->tstamp.tv_sec = 0;
	pkt->tstamp.tv_nsec = 0;
	pkt->buflen = buflen;
	memcpy(pkt->buf, buf, buflen);
	return pkt;
}/*}}}*/

void packet_fill(struct packet *pkt, size_t ipoffset)/*{{{*/
{
	pkt->ip = (struct libnet_ipv4_hdr *)(pkt->buf + ipoffset);
	assert(pkt->ip->ip_v == 4);

	pkt->icmp = (struct libnet_icmpv4_hdr *)(pkt->buf + ipoffset +
							pkt->ip->ip_hl*4);

	switch(pkt->ip->ip_p) {
	case IPPROTO_ICMP: {
		size_t icmplen = 0;
		switch(pkt->icmp->icmp_type) {
		default:
		case ICMP_IREQ:
		case ICMP_IREQREPLY:
		case ICMP_PARAMPROB:
		case ICMP_ROUTERADVERT:
		case ICMP_ROUTERSOLICIT:
		case ICMP_SOURCEQUENCH:
		case ICMP_ECHO:
		case ICMP_ECHOREPLY:
			icmplen = LIBNET_ICMPV4_ECHO_H;
			break;
		case ICMP_UNREACH:
			icmplen = LIBNET_ICMPV4_UNREACH_H;
			break;
		case ICMP_REDIRECT:
			icmplen = LIBNET_ICMPV4_REDIRECT_H;
			break;
		case ICMP_TIMXCEED:
			icmplen = LIBNET_ICMPV4_TIMXCEED_H;
			break;
		case ICMP_TSTAMP:
		case ICMP_TSTAMPREPLY:
			icmplen = LIBNET_ICMPV4_TS_H;
			break;
		case ICMP_MASKREQ:
		case ICMP_MASKREPLY:
			icmplen = LIBNET_ICMPV4_MASK_H;
			break;
		}
		pkt->payload = (uint8_t *)(pkt->icmp) + icmplen;
		break;
	}
	case IPPROTO_UDP:
		pkt->payload = (uint8_t *)(pkt->udp) + LIBNET_UDP_H;
		break;
	case IPPROTO_TCP:
		logd(LOG_FATAL, "%s bug! we do not sniff TCP\n", __func__);
		break;
	default:
		logd(LOG_FATAL, "%s unknown ip proto\n", __func__);
		break;
	}
}/*}}}*/
