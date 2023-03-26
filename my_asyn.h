#ifndef MY_ASYN_H
#define MY_ASYN_H

#include <QThread>
#include <QMutex>
#include <QWaitCondition>

#include <QQueue>
#include <pcap/pcap.h>

#include "my_pkt.h"

namespace MyAsyn{
    extern QQueue<struct My_Pkt>buffer;
    extern QMutex mutex;

    extern QWaitCondition not_empty_cond;
    extern volatile bool capturing;
}

extern void print_pkt(struct My_Pkt *pkt_res);


class Producer:public QThread
{
    Q_OBJECT
public:
//    Producer();
    void set_listen_nic(char*);
    void run() override;

signals:
    void Find_datalink_type(int type);

public slots:
    void stop_pcap(){
        pcap_breakloop(handle);
    }

private:
    char* cur_Nic_name;
    pcap_t *handle;
};


class Consumer:public QThread
{
    Q_OBJECT
public:
//    Consumer();

    void run() override;

signals:
    void Get_one_pkt(struct My_Pkt pkt);

private:
    QQueue<struct My_Pkt> Consumer_buf;
};


#endif // MY_ASYN_H
