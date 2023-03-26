#include <QDebug>
#include <pcap/pcap.h>

#include "my_asyn.h"

namespace MyAsyn{
    QQueue<struct My_Pkt>buffer;
    QMutex mutex;

    QWaitCondition not_empty_cond;
    volatile bool capturing = false;
}

void Add_one_pkt_to_buffer(u_char *userarg, const struct pcap_pkthdr* pkthdr, const u_char* packet);
//void Producer::set_listen_nic(char *nic_name);


void Producer::run()
{
    char errbuf[PCAP_ERRBUF_SIZE];      /* Error string */
    char tmp_str[65535] = {'\0'};

    handle = pcap_create(Producer::cur_Nic_name, errbuf);			/* Session handle */
    if(handle == NULL){
        qDebug()<< QString("Couldn't open handler of device %1:\n").arg(cur_Nic_name);
        qDebug()<<QString(tmp_str);
        return;
    }

    int datalink_type = pcap_datalink(handle);


    if(0 != pcap_setnonblock(handle, 1, errbuf) ){
        qDebug()<< QString("Couldn't set handler of device %1 to nonBlock mode: %2\n").arg(cur_Nic_name).arg(errbuf);
        return;
    }

    pcap_set_immediate_mode(handle, 1);

    pcap_activate(handle);

    // pcap_loop will loop forver
    // unless some conditions changed.
    qDebug()<<"start to loop capturing";
    while(MyAsyn::capturing){
        pcap_dispatch(handle, 0, Add_one_pkt_to_buffer, NULL);
        MyAsyn::not_empty_cond.wakeAll();
    }

    qDebug()<< "Producer existing...";
}


void Consumer::run()
{
    qDebug()<<"Consumer run!";
    while(MyAsyn::capturing){
        MyAsyn::mutex.lock();
        while(MyAsyn::buffer.size()<=0){
            // in case of exiting after there is no pkt in buffer.
            if (!MyAsyn::capturing){
                MyAsyn::mutex.unlock();
                qDebug()<< "Consumer existing...";
                return;
            }

            MyAsyn::not_empty_cond.wait(&MyAsyn::mutex);
        }

        struct My_Pkt pkt_got(
                            MyAsyn::buffer.dequeue()
                        );

        qDebug()<<"Consumer:";
        print_pkt(& pkt_got);

        //here, we should send the pkt_got to model
        emit Get_one_pkt(pkt_got);

        MyAsyn::mutex.unlock();
    }
    qDebug()<< "Consumer existing...";
}


void Producer::set_listen_nic(char * nic_name){
    this->cur_Nic_name = nic_name;
}


void Add_one_pkt_to_buffer(u_char *userarg, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{

    struct My_Pkt* pkt_res = new struct My_Pkt;

    pkt_res->pkt_cnt = new u_char[pkthdr->len];
    memcpy(pkt_res->pkt_cnt,packet,pkthdr->caplen);
    memcpy(&(pkt_res->pkthdr), pkthdr, sizeof(struct pcap_pkthdr));

    // Critical section
    MyAsyn::mutex.lock();
    MyAsyn::buffer.enqueue(*pkt_res);
    MyAsyn::mutex.unlock();

    qDebug()<<"Producer:";
    print_pkt(pkt_res);

    // ont pkt sent, wake the consumer
    MyAsyn::not_empty_cond.wakeAll();
}
