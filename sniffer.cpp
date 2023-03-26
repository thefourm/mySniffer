#include "sniffer.h"
#include "ui_sniffer.h"
#include "packet_list_model_v2.h"
# include "my_asyn.h"

#include <QMetaType>

#include <QDebug>
#include <algorithm>
#include <pcap/pcap.h>




Sniffer::Sniffer(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Sniffer)
{
    ui->setupUi(this);

    // set model.
    packet_list_model *mymodel = new packet_list_model(this);
    ui->packets_list->setModel(mymodel);

    // Register strcut My_Pkt,
    // Otherwise, My_Pkt won't be transmit in signal & plot.
    qRegisterMetaType<My_Pkt>("My_Pkt");
    qRegisterMetaType<My_Pkt>("My_Pkt&");


    // connect: cap 1 pkt for test.
    connect(ui->cap_1_pkt_btn, &QAbstractButton::clicked,
            mymodel, [=](){
                            mymodel->cur_Nic_name = this->cur_NIC;
                            mymodel->packet_list_model::listen_packet();}
    );


    // connect: start capture btn.
    connect(ui->star_capture_btn, &QAbstractButton::clicked,
            mymodel, [=](){
                            qDebug()<<"start_capture_btn clicked!";

                            // SHOULD remove all pkts.
                            mymodel->Remove_pkts(0, mymodel->get_pkt_list_size());

                            qDebug()<<"Remove_pks succeed!";

                            MyAsyn::capturing = true;
                            mymodel->cap_thread.set_listen_nic(this->cur_NIC);

                            mymodel->cap_thread.start();
                            mymodel->add_pkt_thread.start();
        }
    );

    // connect: end capture btn.
    connect(ui->end_cap_btn, &QAbstractButton::clicked, &(mymodel->cap_thread), &Producer::stop_pcap);
    connect(ui->end_cap_btn, &QAbstractButton::clicked,
            mymodel, [=](){
                            MyAsyn::capturing = false;


                            MyAsyn::not_empty_cond.notify_all();

                            // BUGGY: there should notify Producer to exit pcap_loop().


//                            mymodel->cap_thread.quit();
//                            mymodel->add_pkt_thread.quit();
                            mymodel->cap_thread.wait();
                            mymodel->add_pkt_thread.wait();
                            MyAsyn::buffer.clear();
        }
    );

    connect(&(mymodel->cap_thread),&Producer::Find_datalink_type,\
            mymodel, &packet_list_model::set_datalink_type,\
            Qt::BlockingQueuedConnection);

    connect(&(mymodel->add_pkt_thread), &Consumer::Get_one_pkt, \
            mymodel, &packet_list_model::add_one_pkt
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

