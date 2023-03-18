#ifndef SNIFFER_H
#define SNIFFER_H

#include <QWidget>
#include <pcap/pcap.h>

QT_BEGIN_NAMESPACE
namespace Ui { class Sniffer; }
QT_END_NAMESPACE

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

    pcap_if_t *cur_NIC;

    void FindNIC();
    void TEST_NIC();

};
#endif // SNIFFER_H
