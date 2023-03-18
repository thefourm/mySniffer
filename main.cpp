#include "sniffer.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    Sniffer w;
    w.show();
    return a.exec();
}


