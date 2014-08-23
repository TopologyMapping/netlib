#ifndef __SNIFFER_H__
#define __SNIFFER_H__

#include <pcap.h>

struct sniffer;

/* this function creates a thread to capture packets on [iface]. for each
 * packet arriving on [iface], [cb] is called with the sniffer passed as user
 * data. we currently apply a default BPF filter of
 * "dst host ifaceip and (icmp * or udp)". */
struct sniffer * sniffer_create(pcap_if_t *iface, pcap_handler cb);

/* stop capture and wait for capture thread to finish. */
void sniffer_destroy(struct sniffer *sniffer);

#endif
