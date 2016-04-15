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
	// run: iface ttl ipversion probe_type

	log_init(LOG_EXTRA, "log.txt", 1, 1024*1024*16);

	if(!check_permissions()) exit(EXIT_FAILURE);

	if(argc!=5){
		printf("usage: %s iface ttl ipversion probe_type\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	char *iface = argv[1];
	int ttl = atoi(argv[2]);
	int ipversion = atoi(argv[3]); // 4 for ipv4, 6 for ipv6
	int probe_type = atoi(argv[4]); // 1 for icmp, 2 for tcp

	if((probe_type!=1) && (probe_type!=2)){
		printf("unknown probe type\n");
		exit(EXIT_FAILURE);		
	}

	if((ipversion!=4) && (ipversion!=6)){
		printf("unknown ip version\n");
		exit(EXIT_FAILURE);
	}

	if((probe_type==2) && (ipversion==4)){
		printf("tcp only supported in ipv6\n");
		exit(EXIT_FAILURE);
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
		inet_pton(AF_INET6, "2a03:2880:f001:1f:face:b00c:0:25de", &(sa.sin6_addr));
		dst = *((struct sockaddr_storage *) &sa);
		dst.ss_family = AF_INET6;

		if (probe_type==1){
			// ICMP
			q = confirm_query_create6_icmp(&dst, ttl, 1, 1, 1, 1, querycb);
		} else if (probe_type==2){
			// TCP
			q = confirm_query_create6_tcp(&dst, ttl, 0, 1201, 51, 31825, 85, querycb);
		}

		confirm_submit(conf, q);
	}

	sleep(10);

	confirm_destroy(conf);
	demux_destroy();
	log_destroy();
	exit(EXIT_SUCCESS);
}
