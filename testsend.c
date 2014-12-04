#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <libnet.h>
#include "sender.h"
#include "log.h"


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
	/*char *iface = "eth0";
	int ttl = 20;
    int ipversion = 6;// ipversion = 4 to IPv4; ipType = 6 to IPv6;*/

	log_init(LOG_EXTRA, "log.txt", 1, 1024*1024*16);

	struct sender *s = sender_create(iface, ipversion);
	struct packet *pkt;
	struct sockaddr *dst;
	if (ipversion == 4){
        struct sockaddr_in *ipv4_dst = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in ));
        ipv4_dst->sin_family = AF_INET;
        ipv4_dst->sin_addr.s_addr = 2;
        dst = ipv4_dst;
	}
	else if (ipversion == 6){
        struct libnet_in6_addr *ipv6_dst = (struct libnet_in6_addr *)malloc(sizeof(struct libnet_in6_addr ));
        *ipv6_dst = nameToAddr6WithSender(s, "::2");
        dst = ipv6_dst;
	}
	pkt = sender_send_icmp(s, dst, ttl, 1, 1, 1, 1, 1000);
	char *str = packet_tostr(pkt);
	logd(LOG_DEBUG, "%s\n", str);
	free(str);
	packet_destroy(pkt);

	sleep(2);

	/*if (ipversion == 4){
        pkt = sender_send_icmp_fixrev(s, 2, ttl, 1, 1, 1, 1, 1000);
	}
	else if (ipversion == 6){
        struct libnet_in6_addr dst_ipv6;
        dst_ipv6 = nameToAddr6WithSender(s, "::2");
        pkt = sender_send_icmp6(s, dst_ipv6, ttl, 1, 1, 1, 1, 1000);
	}
	str = packet_tostr(pkt);
	logd(LOG_DEBUG, "%s\n", str);
	free(str);
	packet_destroy(pkt);*/

	sender_destroy(s);
	log_destroy();
	exit(EXIT_SUCCESS);
}
