#include "my_pkt.h"

#include <QDebug>
#include <cstring>


My_Pkt::My_Pkt(){
    pkt_cnt=nullptr;
};


My_Pkt::My_Pkt(const struct My_Pkt &a)
{
    pkthdr = a.pkthdr;

    pkt_cnt= new u_char[a.pkthdr.len];
    std::memcpy(pkt_cnt, a.pkt_cnt, pkthdr.len);
}


My_Pkt::My_Pkt(const struct pcap_pkthdr* a_pkthdr, const u_char* packet)
{
    pkt_cnt = new u_char[pkthdr.len];
    memcpy(pkt_cnt,packet,pkthdr.caplen);
    memcpy(&pkthdr, &a_pkthdr, sizeof(pkthdr));
}


My_Pkt::~My_Pkt(){
    if(nullptr!=pkt_cnt){
        delete []pkt_cnt;
        pkt_cnt=nullptr;
    }
};


void print_pkt(struct My_Pkt *pkt_res){
    char tmp_str[65535]={'\0'};
    for(int i=0; i<pkt_res->pkthdr.len; i++){
        tmp_str[i] = isprint(pkt_res->pkt_cnt[i])? pkt_res->pkt_cnt[i]: '.';
    }
    tmp_str[pkt_res->pkthdr.caplen] = '\0';
    qDebug()<<QString("Packet with length of %1 of %2:").arg(pkt_res->pkthdr.caplen).arg(pkt_res->pkthdr.len);
    qDebug()<<QString(tmp_str);
    qDebug()<<'\n';
}
