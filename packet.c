#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "packet.h"
#include "log.h"

static struct packet * packet_create(const uint8_t *buf, size_t buflen, size_t ipoffset);
static void packet_fill(struct packet *pkt, size_t ipoffset);

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
	pkt->ip = orig->ip;
	pkt->ipv6 = orig->ipv6;
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
	char buf1[4096];
	char buf2[4096];
	char buf3[4096];

	if (pkt->ipversion == 4){
		char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(pkt->ip->ip_src), src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(pkt->ip->ip_dst), dst, INET_ADDRSTRLEN);


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
	}
	else if (pkt->ipversion == 6){
        char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &(pkt->ipv6->ip_src), src, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(pkt->ipv6->ip_dst), dst, INET6_ADDRSTRLEN);

		sprintf(buf1, 	"IP hdrlen %d tos 0x%x len %d\n"
				"IP ttl %d proto %d \n"
				"IP src %s 0x%x\n"
				"IP dst %s 0x%x\n",
				(int)pkt->ipv6->ip_hl * 4,
				(int)pkt->ipv6->ip_flags[1],
				(int)ntohs(pkt->ipv6->ip_len),
				(int)pkt->ipv6->ip_hl,
				(int)pkt->ipv6->ip_nh,
				src, (int)pkt->ipv6->ip_src.libnet_s6_addr,
				dst, (int)pkt->ipv6->ip_dst.libnet_s6_addr);

		uint8_t proto = pkt->ipv6->ip_nh;

		switch(proto) {
		case IPPROTO_ICMP:
			sprintf(buf2, 	"ICMP type %d code %d chksum 0x%x",
					pkt->icmpv6->icmp_type,
					pkt->icmpv6->icmp_code,
					ntohs(pkt->icmpv6->icmp_sum));
			uint8_t type = pkt->icmpv6->icmp_type;
			if(type == ICMP6_ECHOREPLY || type == ICMP6_ECHO) {
				sprintf(buf3,	"\nICMP id %d seq %d",
						ntohs(pkt->icmpv6->id),
						ntohs(pkt->icmpv6->seq));
			}
			strcat(buf2, buf3);
			break;
		default:
			sprintf(buf2, "transport protocol not supported");
			break;
		}
	}

	strcat(buf1, buf2);

	char *ret = strdup(buf1);
	if(!ret) logea(__FILE__, __LINE__, NULL);
	return ret;
}/*}}}*/



static struct packet * packet_create(const uint8_t *buf, size_t buflen, size_t ipoffset)/*{{{*/
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

void packet_fill(struct packet *pkt, size_t ipoffset)/*{{{*/
{
	if (pkt->ipversion == 4){
		pkt->ip = (struct libnet_ipv4_hdr *)(pkt->buf + ipoffset);
		assert(pkt->ip->ip_v == 4);

		pkt->icmp = (struct libnet_icmpv4_hdr *)(pkt->buf + ipoffset + pkt->ip->ip_hl*4);
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
	}
	else if (pkt->ipversion == 6){
		pkt->ipv6 = (struct libnet_ipv6_hdr *)(pkt->buf + ipoffset);
		pkt->icmpv6 = (struct libnet_icmpv6_hdr *)(pkt->buf + ipoffset + LIBNET_IPV6_H);

		char ipaddr[INET6_ADDRSTRLEN];

		struct libnet_in6_addr ipv6;

		memcpy(&ipv6, ((struct libnet_in6_addr *) &pkt->ipv6->ip_dst), sizeof(struct libnet_in6_addr));

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
	}
}/*}}}*/

char * sockaddr_tostr(const struct sockaddr_storage *sin)/*{{{*/
{
	if(sin->ss_family != AF_INET && sin->ss_family != AF_INET6)
		return strdup("unknown_ss_family");
	char addr[INET6_ADDRSTRLEN];
	if(sin->ss_family == AF_INET) {
		struct sockaddr_in *ip4 = (struct sockaddr_in *)sin;
		inet_ntop(AF_INET, &(ip4->sin_addr.s_addr), addr, INET6_ADDRSTRLEN);
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

	assert(s1->ss_family == AF_INET || s1->ss_family == AF_INET6);
	return 0;
}/*}}}*/
