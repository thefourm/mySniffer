QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    main.cpp \
#    packet_list_model.cpp \
    my_asyn.cpp \
    my_pkt.cpp \
    packet_list_model_v2.cpp \
    sniffer.cpp

HEADERS += \
#    packet_list_model.h \
    my_asyn.h \
    my_pkt.h \
    packet_list_model_v2.h \
    sniffer.h

FORMS += \
    sniffer.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

LIBS += -L/usr/local/lib -lpcap
#LIBS += -lpcap
