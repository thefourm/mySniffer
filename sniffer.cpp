#include "sniffer.h"
#include "ui_sniffer.h"

#include <QDebug>
#include <pcap/pcap.h>

Q_DECLARE_METATYPE(pcap_if_t*)
Q_DECLARE_METATYPE(pcap_if_t)

Sniffer::Sniffer(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Sniffer)
{
    ui->setupUi(this);
    FindNIC();
}

Sniffer::~Sniffer()
{
    delete ui;
}

void Sniffer::FindNIC(){
    pcap_if_t *NIC_list = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&NIC_list, errbuf) ==-1){
        qDebug()<<"ERR: pcap_findalldevs: "<<errbuf;
        return;
    }

    // list NICs in NIC_box.
    // data in NIC_BOX SHOULD strcut ptr: pcap_if*.
    for(pcap_if_t *cur_NIC = NIC_list; cur_NIC!=NULL; cur_NIC=cur_NIC->next){
        ui->NIC_box->addItem(cur_NIC->name, QVariant::fromValue((void*)cur_NIC));
    }
}

void Sniffer::on_NIC_box_currentIndexChanged(int index)
{
    Sniffer::cur_NIC = (pcap_if_t*)ui->NIC_box->currentData().value<void*>();

    // test wether the NIC is chosen.
    ui->packet_list->setPlainText(cur_NIC->name);
}

