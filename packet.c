#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "packet.h"
#include "log.h"


static void packet4_fill(struct packet *pkt, size_t ipoffset)/*{{{*/
{
	pkt->ip = (struct libnet_ipv4_hdr *)(pkt->buf + ipoffset);
	assert(pkt->ip->ip_v == 4);
	pkt->icmp = (struct libnet_icmpv4_hdr *)
			(pkt->buf + ipoffset + pkt->ip->ip_hl*4);
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
static void packet6_fill(struct packet *pkt, size_t ipoffset)/*{{{*/
{
	pkt->ipv6 = (struct libnet_ipv6_hdr *)(pkt->buf + ipoffset);
	pkt->icmpv6 = (struct libnet_icmpv6_hdr *)
			(pkt->buf + ipoffset + LIBNET_IPV6_H);

	struct libnet_in6_addr ipv6;
	memcpy(&ipv6, (struct libnet_in6_addr *)&pkt->ipv6->ip_dst, sizeof(ipv6));
	char ipaddr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ipv6, ipaddr, INET6_ADDRSTRLEN);

	switch(pkt->ipv6->ip_nh) {
	case IPPROTO_ICMP6: {
		size_t icmplen = 0;
		switch(pkt->icmpv6->icmp_type) {
		default:
		case ICMP6_PARAMPROB:
		case ICMP6_ECHO:
		case ICMP6_ECHOREPLY:
			icmplen = LIBNET_ICMPV6_ECHO_H;
			break;
		case ICMP6_UNREACH:
			icmplen = LIBNET_ICMPV6_UNREACH_H;
			break;
		case ICMP_REDIRECT:
			icmplen = LIBNET_ICMPV6_H;
			break;
		case ICMP6_TIMXCEED:
			icmplen = LIBNET_ICMPV6_H;
			break;
		}
		pkt->payload = (uint8_t *)(pkt->icmpv6) + icmplen;
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
} /*}}}*/
void packet_fill(struct packet *pkt, size_t ipoffset)/*{{{*/
{
	if(pkt->ipversion == 4) packet4_fill(pkt, ipoffset);
	else if(pkt->ipversion == 6) packet6_fill(pkt, ipoffset);
	else { logd(LOG_WARN, "%s.%d: unknown IP ver\n", __FILE__, __LINE__); }
}/*}}}*/

static struct packet * packet_create(const uint8_t *buf, size_t buflen,/*{{{*/
		size_t ipoffset)
{
	struct packet *pkt = malloc(sizeof(*pkt));
	if(!pkt) logea(__FILE__, __LINE__, NULL);
	pkt->buf = malloc(buflen);
	if(!pkt->buf) logea(__FILE__, __LINE__, NULL);
	pkt->tstamp.tv_sec = 0;
	pkt->tstamp.tv_nsec = 0;
	pkt->buflen = buflen;
	pkt->ipversion = (*(buf + ipoffset) & 0xF0) >> 4;
	memcpy(pkt->buf, buf, buflen);
	return pkt;
}/*}}}*/
struct packet * packet_create_eth(const uint8_t *ethbuf, size_t buflen)/*{{{*/
{
	struct packet *pkt = packet_create(ethbuf, buflen, LIBNET_ETH_H);
	packet_fill(pkt, LIBNET_ETH_H);
	return pkt;
}/*}}}*/
struct packet * packet_create_ip(const uint8_t *ipbuf, size_t buflen)/*{{{*/
{
	struct packet *pkt = packet_create(ipbuf, buflen, 0);
	packet_fill(pkt, 0);
	return pkt;
}/*}}}*/

struct packet * packet_clone(const struct packet *orig)/*{{{*/
{
	struct packet *pkt = packet_create(orig->buf, orig->buflen, 0);
	pkt->tstamp = orig->tstamp;
	pkt->ipversion = orig->ipversion;
	// care; depend on union members of the same type (pointers):
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

static char * packet4_tostr(const struct packet *pkt)/*{{{*/
{
	char buf1[1024];
	char buf2[128];
	char buf3[128];

	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(pkt->ip->ip_src), src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(pkt->ip->ip_dst), dst, INET_ADDRSTRLEN);

	sprintf(buf1, "IP hdrlen %d tos 0x%x len %d\n"
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
	switch(proto) {
	case IPPROTO_ICMP:
		sprintf(buf2, "ICMP type %d code %d chksum 0x%x",
				pkt->icmp->icmp_type,
				pkt->icmp->icmp_code,
				ntohs(pkt->icmp->icmp_sum));
		uint8_t type = pkt->icmp->icmp_type;
		if(type != ICMP_ECHOREPLY && type != ICMP_ECHO) break;
		sprintf(buf3, "\nICMP id %d seq %d",
				ntohs(pkt->icmp->icmp_id),
				ntohs(pkt->icmp->icmp_seq));
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
static char * packet6_tostr(const struct packet *pkt)/*{{{*/
{
	char buf1[1024];
	char buf2[128];
	char buf3[128];

	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &(pkt->ipv6->ip_src), src, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &(pkt->ipv6->ip_dst), dst, INET6_ADDRSTRLEN);

	unsigned char *flags = pkt->ipv6->ip_flags;
	uint8_t tc = ((flags[0] & 0x0F) << 4) | ((flags[1] & 0xF0) >> 4);
	uint32_t fl = ((flags[1] & 0xF) << 16) | (flags[2] << 8) | flags[3];
	sprintf(buf1, "IP6 traffic_class 0x%x flow_label 0x%x\n"
			"IP6 ttl %d nh %d len %d\n"
			"IP6 src %s\n"
			"IP6 dst %s\n",
			tc, fl,
			(int)pkt->ipv6->ip_hl,
			(int)pkt->ipv6->ip_nh,
			(int)ntohs(pkt->ipv6->ip_len),
			src, dst);

	uint8_t proto = pkt->ipv6->ip_nh;
	switch(proto) {
	case IPPROTO_ICMP6: {
		sprintf(buf2, "ICMP6 type %d code %d chksum 0x%x",
				pkt->icmpv6->icmp_type,
				pkt->icmpv6->icmp_code,
				ntohs(pkt->icmpv6->icmp_sum));
		uint8_t type = pkt->icmpv6->icmp_type;
		if(type != ICMP6_ECHOREPLY && type != ICMP6_ECHO) break;
		sprintf(buf3, "\nICMP6 id %d seq %d",
				ntohs(pkt->icmpv6->id),
				ntohs(pkt->icmpv6->seq));
		strcat(buf2, buf3);
		break;
	}
	default:
		sprintf(buf2, "transport protocol not supported");
		break;
	}
	strcat(buf1, buf2);

	char *ret = strdup(buf1);
	if(!ret) logea(__FILE__, __LINE__, NULL);
	return ret;
}/*}}}*/
char * packet_tostr(const struct packet *pkt)/*{{{*/
{

	if(pkt->ipversion == 4) return packet4_tostr(pkt);
	else if(pkt->ipversion == 6) return packet6_tostr(pkt);
	else { return NULL; }
}/*}}}*/

char * sockaddr_tostr(const struct sockaddr_storage *sin)/*{{{*/
{
	if(sin->ss_family != AF_INET && sin->ss_family != AF_INET6)
		return strdup("unknown_ss_family");
	char addr[INET6_ADDRSTRLEN];
	if(sin->ss_family == AF_INET) {
		struct sockaddr_in *ip4 = (struct sockaddr_in *)sin;
		inet_ntop(AF_INET, &(ip4->sin_addr), addr, INET6_ADDRSTRLEN);
	} else {
		struct sockaddr_in6 *ip6 = (struct sockaddr_in6 *)sin;
		inet_ntop(AF_INET6, &(ip6->sin6_addr), addr, INET6_ADDRSTRLEN);
	}
	return strdup(addr);
}/*}}}*/
int sockaddr_cmp(const void *vs1, const void *vs2, void *dummy)/*{{{*/
{
	const struct sockaddr_storage *s1 = vs1;
	const struct sockaddr_storage *s2 = vs2;
	assert(s1->ss_family == AF_INET || s1->ss_family == AF_INET6);

	int f = (s1->ss_family > s2->ss_family) -
			(s1->ss_family < s2->ss_family);
	if(f) return f;

	if(s1->ss_family == AF_INET) {
		const struct sockaddr_in *i1 = vs1;
		const struct sockaddr_in *i2 = vs1;
		return memcmp(&(i1->sin_addr), &(i2->sin_addr),
				sizeof(struct in_addr));
	}
	if(s1->ss_family == AF_INET6) {
		const struct sockaddr_in6 *i1 = vs1;
		const struct sockaddr_in6 *i2 = vs1;
		return memcmp(&(i1->sin6_addr), &(i2->sin6_addr),
				sizeof(struct in6_addr));
	}
	return 0;
}/*}}}*/
