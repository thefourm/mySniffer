#include "pkt_analyser.h"
#include "my_pkt.h"

#include <QString>

#include <arpa/inet.h>

#include <netinet/if_ether.h>
#include <netinet/ether.h>

#include <netinet/in.h>
#include <netinet/ip.h>

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <pcap/pcap.h>


//pkt_info::pkt_info()
//{

//}



QString get_pkt_profile(const My_Pkt *pkt){
    QString pkt_profile;
    const u_char* pkt_ptr = pkt->pkt_cnt;

    // get ether_header in my_etherhdr
    ether_header my_etherhdr;
    memcpy(&my_etherhdr, pkt_ptr, sizeof(ethhdr));


    pkt_profile += QString("dst mac: ") + QString(ether_ntoa((struct ether_addr*)my_etherhdr.ether_dhost)) + QString(" ");
    pkt_profile += QString("src mac: ") + QString(ether_ntoa((struct ether_addr*)my_etherhdr.ether_shost)) + QString(" ");

    pkt_ptr += ETHER_HDR_LEN;

    if (my_etherhdr.ether_type == ETHERTYPE_ARP){
        pkt_profile += QString("prtl: ARP");
        return pkt_profile;
    };

    struct ip my_iphdr;
    memcpy(&my_iphdr,pkt_ptr,sizeof(iphdr));
    pkt_profile += QString("dst ip: ") + QString(inet_ntoa(my_iphdr.ip_dst)) + QString(" ");
    pkt_profile += QString("src ip: ") + QString(inet_ntoa(my_iphdr.ip_src)) + QString(" ");
    pkt_ptr += 4*my_iphdr.ip_hl;

    tcphdr my_tcphdr;
    udphdr my_udphdr;
    icmp my_icmphdr;

    pkt_profile += QString("prtl: ");

    switch (my_iphdr.ip_p) {
    case IPPROTO_TCP:
        memcpy(&my_tcphdr, pkt_ptr, sizeof(tcphdr));
        pkt_profile += QString("tcp ") + QString("dst port: ") + QString::number(ntohs(my_tcphdr.th_sport))+ QString(" ") +
                                          QString("src port: ") + QString::number(ntohs(my_tcphdr.th_dport))+ QString(" ");

        break;

    case IPPROTO_UDP:
        memcpy(&my_udphdr, pkt_ptr, sizeof(udphdr));
        pkt_profile += QString("udp ") + QString("dst port: ") + QString::number(ntohs(my_udphdr.uh_dport)) + QString(" ") +
                                          QString("src port: ") + QString::number(ntohs(my_udphdr.uh_sport)) + QString(" ");
        break;

    case IPPROTO_ICMP:
        memcpy(&my_icmphdr, pkt_ptr, sizeof(icmphdr));
        pkt_profile += QString("icmp ") +
                      QString("Type: ") + QString::number(my_icmphdr.icmp_type) + QString(" ") +
                      QString("Code: ") + QString::number(my_icmphdr.icmp_code);
        break;

    default:
        break;
    };

    return pkt_profile;
}
