#include "packet_list_model_v2.h"

#include <QDebug>
#include <pcap/pcap.h>

#include <netinet/if_ether.h>

#include "my_pkt.h"
#include "my_asyn.h"


packet_list_model::packet_list_model(QObject* parent=nullptr)
    :QAbstractListModel(parent)
{
}


int packet_list_model::rowCount(const QModelIndex &parent) const
{
    return packet_list_model::pkt_list.size();
}


QVariant packet_list_model::data(const QModelIndex &index, int role) const
{
    int row = index.row();
    if( !index.isValid() || row>=pkt_list.size())
        return QVariant();

    if(role == Qt::DisplayRole){
        u_char tmp_str[65535]={'\0'};

        for(int i=0; i<pkt_list[row]->pkthdr.len; i++){
            tmp_str[i] = isprint(((pkt_list[row])->pkt_cnt)[i])?    \
                            ((pkt_list[row])->pkt_cnt)[i]:          \
                            '.';
        }

//        QString tmp_qstr = QString(tmp_str);
//        return tmp_qstr;
        return QString((char*)tmp_str);
    }

    else
        return QVariant();
}


Qt::ItemFlags packet_list_model::flags(const QModelIndex &index) const
 {
     if (!index.isValid())
         return Qt::ItemIsEnabled;

     return QAbstractItemModel::flags(index) | Qt::ItemIsEditable;
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


//
bool packet_list_model::Remove_pkts(int index, int num){
    qDebug()<<"here1";
    if (index<0||num<1||index+num<pkt_list.size()) return false;
    qDebug()<<"here2";

    beginRemoveRows(QModelIndex(), index, index+num);
    if(num == pkt_list.size()){
        pkt_list.clear();
        pkt_list.squeeze();
    }
    else{
        pkt_list.remove(index, num);
        pkt_list.squeeze();
    }
    endRemoveRows();

    return true;
}


//void get_link_info(pacp_t *handle){
//    int linktype;
//    if( (linktype=pcap_datalink(handle)) == PCAP_ERROR ){
//        fprintf(std::stderr,"pcap_datalink():%s",pcap_geterr(handle));
//    }
//}


// return: address of the pkt stored (in heap).
struct My_Pkt* capture_one_packet(char* cur_Nic_name, char* filter)
{
    char errbuf[PCAP_ERRBUF_SIZE];      /* Error string */
    char (&tmp_str)[PCAP_ERRBUF_SIZE] =errbuf;

    char *dev=cur_Nic_name;             /* The device to sniff on */
    struct pcap_pkthdr pkthdr;          /* The header that pcap gives us */

    // the 4th param indicate how long should capture wait before send pkt to our buf.
    pcap_t *handle = pcap_open_live(dev, PCAP_BUF_SIZE, 1, NULL, errbuf);			/* Session handle */

    //ERROR handled BUGGY
    if(handle == NULL){
        qDebug()<< QString("Couldn't open handler of device %1: %2\n").arg(dev).arg(errbuf);
        return nullptr;
    }

    /* Grab a packet */
    /* Store it in pkt_res */
    /* Renturn pkt_res */
    const u_char *packet = pcap_next(handle, &pkthdr);

    struct My_Pkt* pkt_res = new struct My_Pkt;

    pkt_res->pkt_cnt = new u_char[pkthdr.len];
    memcpy(pkt_res->pkt_cnt,packet,pkthdr.caplen);
    memcpy(&(pkt_res->pkthdr), &pkthdr, sizeof(pkthdr));


    //try to print content in pkt_res.
    for(int i=0; i<pkt_res->pkthdr.len; i++){
        tmp_str[i] = isprint(pkt_res->pkt_cnt[i])? pkt_res->pkt_cnt[i]: '.';
    }
    tmp_str[pkt_res->pkthdr.caplen] = '\0';
    qDebug()<<QString("Jacked a packet with length of %1 of %2").arg(pkthdr.caplen).arg(pkthdr.len);
    qDebug()<<QString(tmp_str);


    /* And close the session */
    pcap_close(handle);

    return pkt_res;
}


void packet_list_model::listen_packet(){

    const struct My_Pkt* pkt = capture_one_packet(this->cur_Nic_name, NULL);

    int row = rowCount(QModelIndex()) ;
    beginInsertRows(QModelIndex(), row, row);

    packet_list_model::pkt_list.append(pkt);

    endInsertRows();
}


void packet_list_model::add_one_pkt(My_Pkt pkt)
{
    struct My_Pkt *pkt_to_add = new struct My_Pkt(pkt);

    qDebug()<<"list_model:";
    print_pkt(pkt_to_add);

    int row = rowCount(QModelIndex()) ;
    beginInsertRows(QModelIndex(), row, row);
    pkt_list.append(pkt_to_add);
    endInsertRows();
}

