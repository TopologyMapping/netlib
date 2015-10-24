#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include "demux.h"
#include "confirm.h"
#include "log.h"
#include "sender4.h"
#include "packet.h"


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
	char *dstaddr = sockaddr_tostr(&q->dst);
	char *ipaddr = sockaddr_tostr(&q->ip);
	printf("dst %s ttl %d ip %s\n", dstaddr, (int)q->ttl, ipaddr);
	free(dstaddr);
	free(ipaddr);
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

	demux_init(iface);
	struct confirm *conf = confirm_create(iface);

	struct confirm_query *q;
	struct sockaddr_storage dst;
	if (ipversion == 4){
		struct sockaddr_in ipv4_dst;
		ipv4_dst.sin_family = AF_INET;
		inet_pton(AF_INET, "200.149.119.183", &(ipv4_dst.sin_addr));
		dst = *((struct sockaddr_storage *) &ipv4_dst);
		dst.ss_family = AF_INET;
		q = confirm_query_create4(&dst, ttl, 1, 1, 1, 0, querycb);
		confirm_submit(conf, q);
		q = confirm_query_create4(&dst, ttl+1, 1, 1, 1, 0, querycb);
		confirm_submit(conf, q);
	}
	else if (ipversion == 6){
		struct sockaddr_in6 sa;
		sa.sin6_family = AF_INET6;
		inet_pton(AF_INET6, "2800:3F0:4004:800:0:0:0:1012", &(sa.sin6_addr));
		dst = *((struct sockaddr_storage *) &sa);
		dst.ss_family = AF_INET6;
		q = confirm_query_create6(&dst, ttl, 1, 1, 0, 0, querycb);
		confirm_submit(conf, q);
		q = confirm_query_create6(&dst, ttl+1, 1, 1, 0, 0, querycb);
		confirm_submit(conf, q);
	}

	sleep(10);

	confirm_destroy(conf);
	demux_destroy();
	log_destroy();
	exit(EXIT_SUCCESS);
}
