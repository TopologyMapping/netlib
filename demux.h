#ifndef __DEMUX_H__
#define __DEMUX_H__

#include "packet.h"

#define DEMUX_BUFSZ 8096 /* maximum number of packets pending for processing */

/* the demuxer is a singleton entity that listens on a given interface
 * and calls listener functions for each arriving on that interface. */
int demux_init(const char *ifname);
void demux_destroy(void);

typedef int (*demux_listener_fn)(const struct packet *pkt, void *data);

/* listeners need to duplicate packet data if they need to store it. */
void demux_listener_add(demux_listener_fn, void *data);
void demux_listener_del(demux_listener_fn, void *data);

#endif
