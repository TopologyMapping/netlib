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

static int sniffer_openpcap_bpf(struct sniffer *s, pcap_if_t *iface) /* {{{ */
{
	struct bpf_program bpf;
	memset(&bpf, 0, sizeof(bpf));
	char hosts[512];
	hosts[0] = '\0';
	pcap_addr_t *paddr;
	for(paddr = iface->addresses; paddr; paddr = paddr->next) {
		char hostbuf[80];
		char addr[INET6_ADDRSTRLEN];
		struct sockaddr *saddr = paddr->addr;
		if(saddr->sa_family == AF_INET) {
			struct sockaddr_in *sin;
			sin = (struct sockaddr_in *)paddr->addr;
			inet_ntop(AF_INET, &sin->sin_addr, addr,
					INET6_ADDRSTRLEN);
		}
		else if(saddr->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin6;
			sin6 = (struct sockaddr_in6 *)paddr->addr;
			inet_ntop(AF_INET6, &sin6->sin6_addr, addr,
					INET6_ADDRSTRLEN);
		} else {
			continue;
		}
		sprintf(hostbuf, "(host %s) or ", addr);
		if(strlen(hosts) + strlen(hostbuf) > 500)
			goto out_lots;
		strcat(hosts, hostbuf);
	}
	if(strlen(hosts) == 0) goto out_ips;
	*(strrchr(hosts, ')')+1) = '\0'; // remove trailing " or "

	char bpfstr[1024];
	sprintf(bpfstr, "(ip or ip6) and (%s) and not tcp", hosts);
	logd(LOG_INFO, "configuring bpf filter: %s\n", bpfstr);

	if(pcap_compile(s->pcap, &bpf, bpfstr, 1, PCAP_NETMASK_UNKNOWN))
		goto out_compile;
	if(pcap_setfilter(s->pcap, &bpf))
		goto out_setfilter;
	pcap_freecode(&bpf);
	return 0;

	out_lots:
	logd(LOG_WARN, "%s too many addresses in %s\n", __func__, iface->name);
	return -1;
	out_ips:
	logd(LOG_WARN, "%s no address in %s\n", __func__, iface->name);
	return -1;
	out_setfilter:
	logd(LOG_WARN, "%s:%d %s\n", __FILE__, __LINE__, pcap_geterr(s->pcap));
	pcap_freecode(&bpf);
	out_compile:
	logd(LOG_WARN, "%s:%d [%s]\n", __FILE__, __LINE__, pcap_geterr(s->pcap));
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
