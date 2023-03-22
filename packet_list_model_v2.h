#ifndef PACKET_LIST_MODEL_V2_H
#define PACKET_LIST_MODEL_V2_H

#include <QAbstractTableModel>
#include <QVector>
#include <pcap/pcap.h>

struct My_Pkt{
    u_char* pkt_cnt;
    struct pcap_pkthdr pkthdr;

    My_Pkt(){
        pkt_cnt=nullptr;
    };
    ~My_Pkt(){
        if(nullptr!=pkt_cnt){
            delete []pkt_cnt;
            pkt_cnt=nullptr;
        }
    };
};

class packet_list_model : public QAbstractListModel
{
    Q_OBJECT
public:
    char* cur_Nic_name;

    packet_list_model(QObject *parent);

    int rowCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
    Qt::ItemFlags flags(const QModelIndex &index) const;
//    bool setData(const QModelIndex &index, const QVariant &value, int role=Qt::EditRole);

//    bool insertRows(int row, int count=1, const QModelIndex &parent = QModelIndex());
//    bool insert_packet(int row, const u_char* packet_content);

public slots:
    void listen_packet();

private:
    // CAUTION: delete when not used.
    QVector<const My_Pkt*> pkt_list;

};



#endif // PACKET_LIST_MODEL_V2_H
