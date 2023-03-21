#ifndef PACKET_LIST_MODEL_H
#define PACKET_LIST_MODEL_H

#include <QAbstractTableModel>
#include <pcap/pcap.h>

class packet_list_model : public QAbstractListModel
{
    Q_OBJECT
public:
    char* cur_Nic_name;

    packet_list_model(QObject *parent);

    int rowCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
    Qt::ItemFlags flags(const QModelIndex &index) const;
    bool setData(const QModelIndex &index, const QVariant &value, int role=Qt::EditRole);

//    bool insertRows(int row, int count, const QModelIndex &parent = QModelIndex());
    bool insert_packet_profile(int row, const QString &packet_content);

public slots:
    void listen_packet();

private:
    QStringList stringlist;

};



#endif // PACKET_LIST_MODEL_H
