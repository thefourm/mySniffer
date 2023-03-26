#ifndef PKT_FILTER_H
#define PKT_FILTER_H

#include <pcap/pcap.h>

bool my_set_pkt_filter(pcap_t* handler, char* filter);

#endif // PKT_FILTER_H
