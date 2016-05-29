#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>

#include "demux.h"
#include "confirm.h"
#include "log.h"
#include "sender4.h"
#include "packet.h"

#define TESTLIB_PROBE_TCP 1
#define TESTLIB_PROBE_ICMP 2

pthread_mutex_t cbmutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cbcond = PTHREAD_COND_INITIALIZER;

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
	pthread_mutex_lock(&cbmutex);
	char *dstaddr = sockaddr_tostr(&q->dst);
	char *ipaddr = sockaddr_tostr(&q->ip);
	printf("dst %s ttl %d ip %s\n", dstaddr, (int)q->ttl, ipaddr);
	free(dstaddr);
	free(ipaddr);
	confirm_query_destroy(q);
	pthread_cond_signal(&cbcond);
	pthread_mutex_unlock(&cbmutex);
}/*}}}*/

int main(int argc, char **argv)
{
	// run: iface dst_ip start_ttl max_ttl ttl ipversion probe_type
	if(!check_permissions()) exit(EXIT_FAILURE);

	if(argc!=7){
		printf("usage: %s iface dst_ip start_ttl max_ttl ipversion probe_type\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	char *iface = argv[1];
	char *dst_ip_str = argv[2];
	int start_ttl = atoi(argv[3]);
	int max_ttl = atoi(argv[4]);
	int ipversion = atoi(argv[5]); // 4 for ipv4, 6 for ipv6
	char *probe_type_str = argv[6];
	int probe_type;

	// Check probe type
	if(strcmp(probe_type_str, "icmp")==0){
		probe_type = TESTLIB_PROBE_ICMP;
	}
	else if(strcmp(probe_type_str, "tcp")==0){
		probe_type = TESTLIB_PROBE_TCP;
	}
	else {
		printf("unknown probe type\n");
		exit(EXIT_FAILURE);	
	}

	// Check max ttl
	if(max_ttl<start_ttl){
		printf("max_ttl should be at least start_ttl\n");
		exit(EXIT_FAILURE);	
	}

	// Check ip version
	if((ipversion!=4) && (ipversion!=6)){
		printf("unknown ip version\n");
		exit(EXIT_FAILURE);
	}

	if((probe_type==TESTLIB_PROBE_TCP) && (ipversion==4)){
		printf("tcp only supported in ipv6\n");
		exit(EXIT_FAILURE);
	}

	log_init(LOG_EXTRA, "log.txt", 1, 1024*1024*16);
	srand(time(NULL));
	demux_init(iface);
	struct confirm *conf = confirm_create(iface);

	printf("Sending IPv%d %s probes to %s from ttl=%d to ttl=%d\n", ipversion, probe_type_str, dst_ip_str, start_ttl, max_ttl);

	int ttl;
	for(ttl=start_ttl; ttl<=max_ttl; ttl++){
		struct confirm_query *q;
		struct sockaddr_storage dst;

		if (ipversion == 4){
			struct sockaddr_in ipv4_dst;
			ipv4_dst.sin_family = AF_INET;
			inet_pton(AF_INET, dst_ip_str, &(ipv4_dst.sin_addr));
			dst = *((struct sockaddr_storage *) &ipv4_dst);
			dst.ss_family = AF_INET;
			q = confirm_query_create4(&dst, ttl, 1, 1, 1, 0, querycb);
		}
		else if (ipversion == 6){
			struct sockaddr_in6 sa;
			sa.sin6_family = AF_INET6;
			inet_pton(AF_INET6, dst_ip_str, &(sa.sin6_addr));
			dst = *((struct sockaddr_storage *) &sa);
			dst.ss_family = AF_INET6;
			if (probe_type==TESTLIB_PROBE_ICMP){ // ICMP
				q = confirm_query_create6_icmp(&dst, ttl, 1, 1, 1, 1, querycb);
			} else if (probe_type==TESTLIB_PROBE_TCP){ // TCP
				q = confirm_query_create6_tcp(&dst, ttl, 0, 1201, 51, 33435+(rand()%1000), 80, querycb);
			}
		}

		pthread_mutex_lock(&cbmutex);
		confirm_submit(conf, q);
		pthread_cond_wait(&cbcond, &cbmutex);
		pthread_mutex_unlock(&cbmutex);
	}

	confirm_destroy(conf);
	demux_destroy();
	log_destroy();
	exit(EXIT_SUCCESS);
}
