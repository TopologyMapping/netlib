#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include "demux.h"
#include "confirm.h"
#include "log.h"
#include "sender.h"


int check_permissions(void) { /* {{{ */
	if(getuid() != 0) {
		logd(LOG_FATAL, "you must be root to run this program.\n");
		printf("you must be root to run this program.\n");
		return 0;
	}
	return 1;
} /* }}} */


void querycb(struct confirm_query *q)/*{{{*/
{

	if (q->ip.ss_family == AF_INET){
        char dstaddr[80];
        char ipaddr[80];

        uint32_t ipv4 = (((struct sockaddr_in *) &q->ip)->sin_addr.s_addr);
        uint32_t ipv4_dst = (((struct sockaddr_in *) &q->dst)->sin_addr.s_addr);

		inet_ntop(AF_INET, &ipv4_dst, dstaddr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ipv4, ipaddr, INET_ADDRSTRLEN);
        printf("dst %s ttl %d ip %s\n", dstaddr, (int)q->ttl, ipaddr);
	}
	else {
		char dstaddr[INET6_ADDRSTRLEN];
        char ipaddr[INET6_ADDRSTRLEN];

        struct libnet_in6_addr ipv6;
        struct libnet_in6_addr ipv6_dst;

        memcpy(&ipv6, &(((struct sockaddr_in6 *) &q->ip)->sin6_addr), sizeof(struct libnet_in6_addr));
        memcpy(&ipv6_dst, &(((struct sockaddr_in6 *) &q->dst)->sin6_addr), sizeof(struct libnet_in6_addr));

	  	inet_ntop(AF_INET6, &ipv6_dst, dstaddr, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ipv6, ipaddr, INET6_ADDRSTRLEN);
        printf("dst %s ttl %d ip %s\n", dstaddr, (int)q->ttl, ipaddr);
	}

	confirm_query_destroy(q);

}/*}}}*/


int main(int argc, char **argv)
{
	if(!check_permissions()) { exit(EXIT_FAILURE); }
	if((argc != 3) && (argc != 4)) {
		printf("usage: %s iface ttl\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	char *iface = argv[1];
	int ttl = atoi(argv[2]);
    int ipversion; // ipversion = 4 to IPv4; ipversion = 6 to IPv6;
    if(argc == 4){
        ipversion = atoi(argv[3]);
    }
    else{
        ipversion = 4;
    }

    //char *iface = "eth0";
	//int ttl = 20;
    //int ipversion = 6;

	log_init(LOG_EXTRA, "log.txt", 1, 1024*1024*16);

	demux_init(iface);
	struct confirm *conf = confirm_create(iface);

	struct confirm_query *q;
    struct sockaddr_storage dst;
	if (ipversion == 4){
        struct sockaddr_in ipv4_dst;
        ipv4_dst.sin_family = AF_INET;
        ipv4_dst.sin_addr.s_addr = 2;
        dst = *((struct sockaddr_storage *) &ipv4_dst);
        dst.ss_family = AF_INET;
    }
    else if (ipversion==6){
        struct libnet_in6_addr ipv6_dst;
        struct sockaddr_in6 sa;
        inet_pton(AF_INET6, "::2", &(sa.sin6_addr));
        memcpy(&ipv6_dst, &sa.sin6_addr, sizeof(struct libnet_in6_addr));
        dst = *((struct sockaddr_storage *) &ipv6_dst);
        dst.ss_family = AF_INET6;
    }
    q = confirm_query_create(dst, ttl, 1, 1, 1, 0, querycb);
    confirm_query(conf, q);
    q = confirm_query_create(dst, ttl+1, 1, 0, 1, 0, querycb);
    confirm_query(conf, q);

	sleep(10);

	confirm_destroy(conf);
	demux_destroy();
	log_destroy();
	exit(EXIT_SUCCESS);
}
