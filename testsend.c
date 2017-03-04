#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <libnet.h>

#include "sender4.h"
#include "sender6.h"

#include "log/log.h"


int check_permissions(void) { /* {{{ */
	if(getuid() != 0) {
		logd(LOG_FATAL, "you must be root to run this program.\n");
		printf("you must be root to run this program.\n");
		return 0;
	}
	return 1;
} /* }}} */


int main(int argc, char **argv)
{
	if(!check_permissions()) { exit(EXIT_FAILURE); }
	if((argc != 3) && (argc != 4)) {
		printf("usage: %s iface ttl\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	char *iface = argv[1];
	int ttl = atoi(argv[2]);
	int ipversion;// ipversion = 4 to IPv4; ipversion = 6 to IPv6;
	if(argc == 4){
		ipversion = atoi(argv[3]);
	}
	else{
		ipversion = 4;
	}

	log_init(LOG_EXTRA, "log.txt", 1, 1024*1024*16);

	struct packet *pkt;
	struct sender4 *s;
	if (ipversion == 4){
		s = sender4_create(iface);
		pkt = sender4_send_icmp(s, 2, ttl, 1, 1, 1, 1, 1000);
		sender4_destroy(s);
	}
	else if (ipversion == 6){
		struct sender6 *s6 = sender6_create(iface);
		struct libnet_in6_addr ipv6_dst;
		struct sockaddr_in6 sa;
		inet_pton(AF_INET6, "2800:3f0:4004:803::1012", &(sa.sin6_addr));
		memcpy(&ipv6_dst, &sa.sin6_addr, sizeof(struct libnet_in6_addr));
		pkt = sender6_send_icmp(s6, ipv6_dst, ttl, 1, 1, 1, 1, 1, 1000);
		sender6_destroy(s6);
	}

	char *str = packet_tostr(pkt);
	logd(LOG_DEBUG, "%s\n", str);
	free(str);
	packet_destroy(pkt);

	sleep(2);

	if (ipversion == 4){
		pkt = sender4_send_icmp_fixrev(s, 2, ttl, 1, 1, 1, 1, 1000);
	}
	/*else if (ipversion == 6){
        struct libnet_in6_addr dst_ipv6;
        dst_ipv6 = nameToAddr6WithSender(s, "::2");
        pkt = sender_send_icmp6_fixrev(s, dst_ipv6, ttl, 1, 1, 1, 1, 1000);
	}
	str = packet_tostr(pkt);
	logd(LOG_DEBUG, "%s\n", str);
	free(str);
	packet_destroy(pkt);*/

	log_destroy();
	exit(EXIT_SUCCESS);
}
