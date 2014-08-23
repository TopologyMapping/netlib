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
	char dstaddr[80];
	char ipaddr[80];
	inet_ntop(AF_INET, &(q->dst), dstaddr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(q->ip), ipaddr, INET_ADDRSTRLEN);
	printf("dst %s ttl %d ip %s\n", dstaddr, (int)q->ttl, ipaddr);
	confirm_query_destroy(q);
}/*}}}*/


int main(int argc, char **argv)
{
	if(!check_permissions()) { exit(EXIT_FAILURE); }
	if(argc != 3) {
		printf("usage: %s iface ttl\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	char *iface = argv[1];
	int ttl = atoi(argv[2]);
	log_init(LOG_EXTRA, "log.txt", 1, 1024*1024*16);

	demux_init(iface);
	struct confirm *conf = confirm_create(iface);

	struct confirm_query *q;
	q = confirm_query_create(2, ttl, 1, 1, 1, 0, querycb);
	confirm_query(conf, q);
	q = confirm_query_create(2, ttl+1, 1, 0, 1, 0, querycb);
	confirm_query(conf, q);

	sleep(10);

	confirm_destroy(conf);
	demux_destroy();
	log_destroy();
	exit(EXIT_SUCCESS);
}
