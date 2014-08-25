C network probing library
=========================

* ```demux``` the demuxer is a singleton that listens on a given interface (using `sniffer`) and calls listener functions.
* ```sniffer``` the sniffer calls a callback function for each UDP or ICMP packet arriving at a given interface.
* ```packet``` support functions for manipulating and storing packets.
* ```sender``` functions to send ICMP packets; allows fixing the forward and reverse flow identifiers.
* ```confirm``` a module that retransmits probes to address packets losses.

