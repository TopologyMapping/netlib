#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include <pthread.h>
#include <pcap.h>
#include <arpa/inet.h>

#include "log.h"

/*****************************************************************************
 * static declarations
 ****************************************************************************/
struct sniffer {
	char *ifname;
	pcap_t *pcap;
	pcap_handler pcapcb;
	pthread_t pthread;
};

/* Returns 0 on success and 1 on error. */
static void * sniffer_thread(void *vsniffer);
/* Returns UINT32_T if no AF_INET address is found. */
static uint32_t sniffer_getifaddr(pcap_if_t *iface);
/* Returns UCHAR_MAX if no AF_INET6 address is found. */
static unsigned char * sniffer_getifaddr6(pcap_if_t *iface);
/* Returns 0 on success and -1 on error. */
static int sniffer_openpcap_bpf(struct sniffer *s, pcap_if_t *iface);
/* Returns 0 on success and -1 on error. */
static int sniffer_openpcap(struct sniffer *s, pcap_if_t *iface);

/*****************************************************************************
 * Public functions.
 ****************************************************************************/
struct sniffer * sniffer_create(pcap_if_t *iface, pcap_handler cb) /* {{{ */
{
	struct sniffer *s;

	s = malloc(sizeof(struct sniffer));
	if(!s) logea(__FILE__, __LINE__, NULL);

	s->pcapcb = cb;
	s->ifname = malloc(strlen(iface->name)+1);
	if(!s->ifname) logea(__FILE__, __LINE__, NULL);
	strcpy(s->ifname, iface->name);
	if(sniffer_openpcap(s, iface)) goto out;
	if(pthread_create(&s->pthread, NULL, sniffer_thread, s)) goto out_pcap;

	logd(LOG_INFO, "%s dev=%s ok\n", __func__, s->ifname);

	return s;

	out_pcap:
	loge(LOG_FATAL, __FILE__, __LINE__);
	pcap_close(s->pcap);
	out:
	loge(LOG_FATAL, __FILE__, __LINE__);
	free(s->ifname);
	free(s);
	return NULL;
} /* }}} */

void sniffer_destroy(struct sniffer *s) /* {{{ */
{
	int i;
	void *r;
	pcap_breakloop(s->pcap);
	pthread_cancel(s->pthread);
	i = pthread_join(s->pthread, &r);
	if(i || r != PTHREAD_CANCELED) {
		logd(LOG_DEBUG, "%s:%d: join(%s) ret(%p)\n", __FILE__,
				__LINE__, strerror(errno), r);
	}
	pcap_close(s->pcap);
	logd(LOG_INFO, "%s dev=%s ok\n", __func__, s->ifname);
	free(s->ifname);
	free(s);
} /* }}} */

/*****************************************************************************
 * Static functions.
 ****************************************************************************/
static void * sniffer_thread(void *vsniffer) /* {{{ */
{
	struct pcap_stat stats;
	struct sniffer *s = (struct sniffer *)vsniffer;
	if(-1 == pcap_loop(s->pcap, -1, s->pcapcb, (uint8_t *)s)) goto out;
	if(pcap_stats(s->pcap, &stats)) goto out;
	logd(LOG_INFO, "%s %s recv=%d dropped=%d\n", __func__, s->ifname,
			stats.ps_recv, stats.ps_drop);
	pthread_exit(0);

	out:
	logd(LOG_DEBUG, "%s:%d: %s\n", __FILE__, __LINE__,
			pcap_geterr(s->pcap));
	pthread_exit((void *)1);
} /* }}} */

static unsigned char * sniffer_getifaddr6(pcap_if_t *iface) /* {{{ */
{
	pcap_addr_t *paddr;
	for(paddr = iface->addresses; paddr; paddr = paddr->next) {
		struct sockaddr *saddr = paddr->addr;
		if(saddr->sa_family == AF_INET6) {
			struct sockaddr_in6 *inaddr6;
			inaddr6 = (struct sockaddr_in6 *)saddr;
			return inaddr6->sin6_addr.s6_addr;
		}
	}
	logd(LOG_WARN, "%s no AF_INET6 address in %s\n", __func__, iface->name);
	return UCHAR_MAX;
}

static uint32_t sniffer_getifaddr(pcap_if_t *iface) /* {{{ */
{
	pcap_addr_t *paddr;
	for(paddr = iface->addresses; paddr; paddr = paddr->next) {
		struct sockaddr *saddr = paddr->addr;
		if(saddr->sa_family == AF_INET) {
			struct sockaddr_in *inaddr;
			inaddr = (struct sockaddr_in *)saddr;
			return inaddr->sin_addr.s_addr;
		}
	}
	logd(LOG_WARN, "%s no AF_INET address in %s\n", __func__, iface->name);
	return UINT32_MAX;
} /* }}} */

static int sniffer_openpcap_bpf(struct sniffer *s, pcap_if_t *iface) /* {{{ */
{
	struct bpf_program bpf;
	uint32_t ip;
	unsigned char *ipv6;
	char addr[INET_ADDRSTRLEN];
	char addr6[INET6_ADDRSTRLEN];
	char bpfstr4[64];
	char bpfstr6[64];
	char bpfstrfinal[128];
	int hasdst4, hasdst6;
	hasdst4 = 0;
	hasdst6 = 0;

	memset(&bpf, 0, sizeof(struct bpf_program));

	ip = sniffer_getifaddr(iface);
	if(ip != UINT32_MAX) {
		if(inet_ntop(AF_INET, &ip, addr, INET_ADDRSTRLEN)) {
			sprintf(bpfstr4, "(dst host %s)", addr);
			hasdst4 = 1;
		}
	}
	ipv6 = sniffer_getifaddr6(iface);
	if(ipv6 != UCHAR_MAX) {
		if(inet_ntop(AF_INET6, &ipv6, addr6, INET6_ADDRSTRLEN)) {
			sprintf(bpfstr6, "(dst host %s)", addr6);
			hasdst6 = 1;
		}
	}

	if (hasdst4 && hasdst6){
		sprintf(bpfstrfinal, "(%s || %s) && ", bpfstr4, bpfstr6);
	}
	else if (hasdst4){
		sprintf(bpfstrfinal, "%s && ", bpfstr4);
	}
	else if (hasdst6){
		sprintf(bpfstrfinal, "%s && ", bpfstr6);
	}
	strcat(bpfstrfinal, "(icmp || udp)");

	if(pcap_compile(s->pcap, &bpf, bpfstrfinal, 1, 0)) goto out_compile;
	if(pcap_setfilter(s->pcap, &bpf)) goto out_setfilter;
	pcap_freecode(&bpf);
	return 0;

	out_setfilter:
	logd(LOG_DEBUG, "%s:%d: error\n", __FILE__, __LINE__);
	pcap_freecode(&bpf);
	out_compile:
	logd(LOG_DEBUG, "%s:%d: %s\n", __FILE__, __LINE__,
			pcap_geterr(s->pcap));
	out:
	loge(LOG_DEBUG, __FILE__, __LINE__);
	return -1;
} /* }}} */

static int sniffer_openpcap(struct sniffer *s, pcap_if_t *iface) /* {{{ */
{
	char errbuf[PCAP_ERRBUF_SIZE];

	errbuf[0] = '\0';
	s->pcap = pcap_open_live(s->ifname, 65535, 1, 0, errbuf);
	if(strlen(errbuf) > 0) {
		logd(LOG_DEBUG, "%s:%d: %s\n", __FILE__, __LINE__, errbuf);
	}
	if(!s->pcap) {
		logd(LOG_DEBUG, "%s:%d: pcap_open_live failed\n",
				__FILE__, __LINE__);
		goto out;
	}
	if(pcap_datalink(s->pcap) != DLT_EN10MB) goto out_datalink;

	if(sniffer_openpcap_bpf(s, iface)) goto out_bpf;
	if(pcap_setdirection(s->pcap, PCAP_D_IN)) {
		logd(LOG_WARN, "%s IN %s\n", __func__, pcap_geterr(s->pcap));
	}

	logd(LOG_INFO, "%s dev=%s ok\n", __func__, s->ifname);
	return 0;

	out_datalink:
	logd(LOG_DEBUG, "%s:%d: datalink != EN10MB\n", __FILE__, __LINE__,
			pcap_geterr(s->pcap));
	out_bpf:
	loge(LOG_DEBUG, __FILE__, __LINE__);
	pcap_close(s->pcap);
	out:
	return -1;
} /* }}} */

