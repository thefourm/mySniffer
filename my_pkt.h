#ifndef MY_PKT_H
#define MY_PKT_H

#include <QMetaType>

#include <pcap/pcap.h>

struct My_Pkt{
    u_char* pkt_cnt;
    struct pcap_pkthdr pkthdr;

    My_Pkt();
    My_Pkt(const struct pcap_pkthdr* pkthdr, const u_char* packet);
    My_Pkt(const struct My_Pkt& a);
    ~My_Pkt();
};

void print_pkt(struct My_Pkt *pkt_res);

Q_DECLARE_METATYPE(My_Pkt);
Q_DECLARE_METATYPE(pcap_if_t*)
Q_DECLARE_METATYPE(pcap_if_t)

#endif // MY_PKT_H
