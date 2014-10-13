#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

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
	if(argc != 3) {
		printf("usage: %s iface ttl\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	char *iface = argv[1];
	int ttl = atoi(argv[2]);
	log_init(LOG_EXTRA, "log.txt", 1, 1024*1024*16);

	struct sender *s = sender_create(iface);

	struct packet *pkt = sender_send_icmp(s, 2, ttl, 1, 1, 1, 1, 1000);
	char *str = packet_tostr(pkt);
	logd(LOG_DEBUG, "%s\n", str);
	free(str);
	packet_destroy(pkt);

	sleep(2);

	pkt = sender_send_icmp_fixrev(s, 2, ttl, 1, 1, 1, 1, 1000);
	str = packet_tostr(pkt);
	logd(LOG_DEBUG, "%s\n", str);
	free(str);
	packet_destroy(pkt);

	sender_destroy(s);
	log_destroy();
	exit(EXIT_SUCCESS);
}
