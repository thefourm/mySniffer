#include "sniffer.h"
#include "ui_sniffer.h"
#include "packet_list_model.h"

#include <QDebug>
#include <pcap/pcap.h>
#include <algorithm>

Q_DECLARE_METATYPE(pcap_if_t*)
Q_DECLARE_METATYPE(pcap_if_t)

Sniffer::Sniffer(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Sniffer)
{
    ui->setupUi(this);
    packet_list_model *mymodel = new packet_list_model(this);
    ui->packets_list->setModel(mymodel);
    connect(ui->start_cap_btn, &QAbstractButton::clicked,
            mymodel, [=](){
                            mymodel->cur_Nic_name = this->cur_NIC;
                            mymodel->packet_list_model::listen_packet();}
    );
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
//        ui->NIC_box->addItem(cur_NIC->name, QVariant::fromValue((void*)cur_NIC));
        ui->NIC_box->addItem(cur_NIC->name);

    }
    pcap_freealldevs(NIC_list);
}


// change the candidate NIC to sniff on.
void Sniffer::on_NIC_box_currentIndexChanged(int index)
{
//    Sniffer::cur_NIC = (pcap_if_t*)ui->NIC_box->currentData().value<void*>();

    QString tmp = ui->NIC_box->currentText();
    std::copy(tmp.toStdString().begin(), tmp.toStdString().end(), this->cur_NIC);

    // test wether the NIC is chosen.
    ui->current_Nic->setPlainText(cur_NIC);
}

