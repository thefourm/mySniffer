#ifndef PACKET_LIST_MODEL_V2_H
#define PACKET_LIST_MODEL_V2_H

#include <QAbstractTableModel>
#include <QVector>
#include <pcap/pcap.h>

#include "my_pkt.h"
#include "my_asyn.h"


class packet_list_model : public QAbstractListModel
{
    Q_OBJECT
public:
    char* cur_Nic_name;
    Producer cap_thread;
    Consumer add_pkt_thread;

    packet_list_model(QObject *parent);

    int rowCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
    Qt::ItemFlags flags(const QModelIndex &index) const;
//    bool setData(const QModelIndex &index, const QVariant &value, int role=Qt::EditRole);

//    bool insertRows(int row, int count=1, const QModelIndex &parent = QModelIndex());
//    bool insert_packet(int row, const u_char* packet_content);

    int get_pkt_list_size(){
        return pkt_list.size();
    }

public slots:
    void listen_packet();
    void add_one_pkt(struct My_Pkt pkt);

    bool Remove_pkts(int index, int num);

private:
    // CAUTION: delete when not used.
    QVector<const My_Pkt*> pkt_list;

};



#endif // PACKET_LIST_MODEL_V2_H
