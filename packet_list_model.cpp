#include "packet_list_model.h"

#include <QDebug>
#include <pcap/pcap.h>

#include <netinet/if_ether.h>

packet_list_model::packet_list_model(QObject* parent=nullptr)
    :QAbstractListModel(parent)
{

}

int packet_list_model::rowCount(const QModelIndex &parent) const
{
    return packet_list_model::stringlist.count();
}

QVariant packet_list_model::data(const QModelIndex &index, int role) const
{
    if( !index.isValid() || index.row()>=stringlist.size())
        return QVariant();

    if(role == Qt::DisplayRole)
        return stringlist.at(index.row());
    else
        return QVariant();
}

Qt::ItemFlags packet_list_model::flags(const QModelIndex &index) const
 {
     if (!index.isValid())
         return Qt::ItemIsEnabled;

     return QAbstractItemModel::flags(index) | Qt::ItemIsEditable;
 }

bool packet_list_model::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if (index.isValid() && role == Qt::EditRole) {
        stringlist.replace(index.row(), value.toString());
        emit dataChanged(index, index);
        return true;
    }

    return false;
}


//bool packet_list_model::insertRows(int row, int count, const QModelIndex &parent = QModelIndex()){
//    if(row<0||count<1)  return false;

//    beginInsertRows(parent, row, row+count-1);
//    for(int i=row; i<row+count; i++){
//        packet_list_model::stringlist.append();
//    }
//    endInsertRows();
//    return true;
//}


bool packet_list_model::insert_packet_profile(int row, const QString &packet_content){
    if(row<0)   return false;
    beginInsertRows(QModelIndex(), row, row);

    packet_list_model::stringlist.append(packet_content);

    endInsertRows();
    return true;
}

QString capture_one_packet(char* cur_Nic_name, char* filter)
{
    char errbuf[PCAP_ERRBUF_SIZE];      /* Error string */
    char pktbuf[65535];
    char *dev=cur_Nic_name;             /* The device to sniff on */
    struct pcap_pkthdr pkthdr;          /* The header that pcap gives us */

    pcap_t *handle = pcap_open_live(dev, PCAP_BUF_SIZE, 0, NULL, errbuf);			/* Session handle */

    //ERROR handled BUGGY
    if(handle == NULL){
        qDebug()<< QString("Couldn't open handler of device %1: %2\n").arg(dev).arg(errbuf);
        return QString("");
    }

    /* Grab a packet */
    /* copy its content to buf */
    const u_char *packet = pcap_next(handle, &pkthdr);
    for(int i=0; i<pkthdr.len; i++){
        pktbuf[i] = isprint(packet[i])? packet[i]: '.';
    }
    pktbuf[pkthdr.len] = '\0';


    /* Print its length */
    /* And print its payload */
    qDebug()<<QString("Jacked a packet with length of %1 of %2").arg(pkthdr.caplen).arg(pkthdr.len);
    qDebug()<<QString(pktbuf);


    /* And close the session */
    pcap_close(handle);



    return QString(pktbuf);
}


void packet_list_model::listen_packet(){
    char errbuf[PCAP_ERRBUF_SIZE];

    QString packet_content = capture_one_packet(this->cur_Nic_name, NULL);
    qDebug()<<packet_content;

    packet_list_model::insert_packet_profile(this->rowCount(QModelIndex()),packet_content);


}



