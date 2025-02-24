TEMPLATE = app
TARGET = qmlvideo

QT += quick multimedia
android: qtHaveModule(androidextras) {
    QT += androidextras
    DEFINES += REQUEST_PERMISSIONS_ON_ANDROID
}

LOCAL_SOURCES = main.cpp
LOCAL_HEADERS = trace.h

SOURCES += $$LOCAL_SOURCES
HEADERS += $$LOCAL_HEADERS
RESOURCES += qmlvideo.qrc

SNIPPETS_PATH = ../snippets
include($$SNIPPETS_PATH/performancemonitor/performancemonitordeclarative.pri)

target.path = $$[QT_INSTALL_EXAMPLES]/multimedia/video/qmlvideo
INSTALLS += target

macos: QMAKE_INFO_PLIST = Info.plist

EXAMPLE_FILES += \
    qmlvideo.png \
    qmlvideo.svg
