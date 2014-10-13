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

	if (q->ipType == 6){
		char dstaddr[INET6_ADDRSTRLEN];
        char ipaddr[INET6_ADDRSTRLEN];
	  	inet_ntop(AF_INET6, &(q->dst_ipv6), dstaddr, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(q->ipv6), ipaddr, INET6_ADDRSTRLEN);
        printf("dst %s ttl %d ip %s\n", dstaddr, (int)q->ttl, ipaddr);
	}
	else if (q->ipType == 4){
        char dstaddr[80];
        char ipaddr[80];
		inet_ntop(AF_INET, &(q->dst), dstaddr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(q->ip), ipaddr, INET_ADDRSTRLEN);
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
    int ipType; // ipType = 4 to IPv4; ipType = 6 to IPv6;
    if(argc == 4){
        ipType = atoi(argv[3]);
    }
    else{
        ipType = 4;
    }

	log_init(LOG_EXTRA, "log.txt", 1, 1024*1024*16);

	demux_init(iface, ipType);
	struct confirm *conf = confirm_create(iface, ipType);

	struct confirm_query *q;
	if (ipType==4){
        q = confirm_query_create(2, ttl, 1, 1, 1, 0, querycb);
        confirm_query(conf, q);
        q = confirm_query_create(2, ttl+1, 1, 0, 1, 0, querycb);
        confirm_query(conf, q);
	}
	else if (ipType==6){
        struct libnet_in6_addr dst_ipv6;
        dst_ipv6 = nameToAddr6WithConfirm(conf, "::2");
        q = confirm_query_create_ipv6(dst_ipv6, ttl, 1, 1, 1, 0, querycb);
        confirm_query(conf, q);
        q = confirm_query_create_ipv6(dst_ipv6, ttl+1, 1, 0, 1, 0, querycb);
        confirm_query(conf, q);
	}

	sleep(10);

	confirm_destroy(conf);
	demux_destroy();
	log_destroy();
	exit(EXIT_SUCCESS);
}
