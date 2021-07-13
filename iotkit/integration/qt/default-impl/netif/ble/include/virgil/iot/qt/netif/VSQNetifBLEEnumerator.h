//  Copyright (C) 2015-2020 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

#ifndef VIRGIL_IOTKIT_QT_BLE_ENUMERATOR_H_
#define VIRGIL_IOTKIT_QT_BLE_ENUMERATOR_H_

#include <QtCore>
#include <QtNetwork>
#include <QtBluetooth>

#include <QAbstractTableModel>

class VSQNetifBLEEnumerator : public QAbstractTableModel {
    Q_OBJECT

    struct BLEDevInfo {
        QBluetoothDeviceInfo info;
        QDateTime lastUpdate;
        bool needInformUser = true;

        BLEDevInfo(const QBluetoothDeviceInfo &inf, const QDateTime &dt) {
            info = inf;
            lastUpdate = dt;
        }

        BLEDevInfo() {
            info = QBluetoothDeviceInfo();
            lastUpdate = QDateTime::currentDateTime().addYears(-1);
        }
    };

    typedef  QMap<QString, BLEDevInfo> VSQBLEDevices;

public:
    enum Element {
        Name = Qt::UserRole,
        Mac,
        Manufacture,
        RSSI,
        Initialized,
        ElementMax
    };

    VSQNetifBLEEnumerator() = default;

    VSQNetifBLEEnumerator(VSQNetifBLEEnumerator const &) = delete;

    VSQNetifBLEEnumerator &
    operator=(VSQNetifBLEEnumerator const &) = delete;

    virtual ~VSQNetifBLEEnumerator() = default;

    /**
     * @brief Start devices discovery
     */
    Q_INVOKABLE void startDiscovery();

    /**
     * @brief Stop devices discovery
     */
    Q_INVOKABLE void stopDiscovery();

    /**
     * @brief Get device information by its name
     */
    QBluetoothDeviceInfo
    devInfo(const QString& mac) const;

    /**
     * QAbstractTableModel implementation
     */
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;

signals:

    /**
     * @brief Emited then discovery finished. New device list can be read by devicesList()
     */
    void fireDiscoveryFinished();

    void
    fireDeviceIsClose(QString deviceMac, QString deviceName, bool requiresProvision);

private slots:

    /**
     * @brief Called when one service discovered
     * @param[in] deviceInfo - instance of discovered device info
     */
    void onDeviceDiscovered(const QBluetoothDeviceInfo & deviceInfo);

    /**
     * @brief Called when devices discovery complitly finished
     */
    void onDiscoveryFinished();

    void onDeviceUpdated(const QBluetoothDeviceInfo &info, QBluetoothDeviceInfo::Fields updatedFields);

private:
    static const int kBLEDiscoverPeriodMS = 2000;
    static const int kInactiveTimeoutMS = 15000;
    static const int kRSSIEdge = -50;
    static const quint16 kManufacturerType = 0x1914;

    bool m_stopped = false;

    VSQBLEDevices m_devices;                                /**< Map of device name -> device info */
    void cleanOldDevices();

    void updateState(const QString &mac);
};

#endif // VIRGIL_IOTKIT_QT_BLE_ENUMERATOR_H_

