#include "pkt_filter.h"

//pkt_filter::pkt_filter()
//{

//}
bool my_set_pkt_filter(pcap_t* handler, char* filter)
{
    if(filter[0] == '\0') return true;

    char errbuf[PCAP_ERRBUF_SIZE];


    struct bpf_program bpf;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;


    // MAYBE Get network dev src ip ad and netmask;


    if( pcap_compile(handler, &bpf, filter, 0, netmask) == PCAP_ERROR){
        fprintf(stderr, "pcap_comple():%s\n", pcap_geterr(handler));
        return false;
    }

    if( pcap_setfilter(handler, &bpf)== PCAP_ERROR ){
        fprintf(stderr, "pcap_setfilter():%s\n", pcap_geterr(handler));
        return false;
    }


    return true;
}
