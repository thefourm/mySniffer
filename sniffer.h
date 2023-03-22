#ifndef SNIFFER_H
#define SNIFFER_H

#include <QWidget>
#include <pcap/pcap.h>

#include "packet_list_model_v2.h"

QT_BEGIN_NAMESPACE
namespace Ui { class Sniffer; }
QT_END_NAMESPACE

const int NIC_NAME_LENGTH = 128;

class Sniffer : public QWidget
{
    Q_OBJECT
    char** NIC_list;
    char* packet_buffer;

public:
    Sniffer(QWidget *parent = nullptr);
    ~Sniffer();

private slots:
    void on_NIC_box_currentIndexChanged(int index);


private:
    Ui::Sniffer *ui;
    packet_list_model *pkt_list_model;

    char cur_NIC[128];

    void FindNIC();
    void TEST_NIC();

};
#endif // SNIFFER_H
