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

#include <virgil/iot/qt/netif/VSQNetifBLEEnumerator.h>

#if !defined(BLE_ENUM_DEBUG)
#define BLE_ENUM_DEBUG 0
#endif


/******************************************************************************/
void
VSQNetifBLEEnumerator::updateState(const QString &mac) {
    const int _pos = m_devices.keys().indexOf(mac);

    const auto _idx = createIndex(_pos, 0);
    emit dataChanged(_idx, _idx);

    auto rssi = m_devices[mac].info.rssi();

    // Get provision state from manufacturer data
    auto data = m_devices[mac].info.manufacturerData(kManufacturerType);
    bool provisioned = false;
    if (data.size() >= 1 && data.at(0) == 0x01) {
        provisioned = true;
    }
    bool requireProvision = !provisioned;

    if (!provisioned && rssi && rssi > kRSSIEdge) {
        if (m_devices[mac].needInformUser) {
            m_devices[mac].needInformUser = false;
            emit fireDeviceIsClose(mac, m_devices[mac].info.name(), requireProvision);
        }
    }
}

/******************************************************************************/
void
VSQNetifBLEEnumerator::onDeviceDiscovered(const QBluetoothDeviceInfo &deviceInfo) {
    if (deviceInfo.coreConfigurations() & QBluetoothDeviceInfo::LowEnergyCoreConfiguration &&
        !deviceInfo.name().isEmpty()) {

#if BLE_ENUM_DEBUG
        qDebug() << "[VIRGIL] Device Discovered : " << deviceInfo.name() << " : " << deviceInfo.deviceUuid();
#endif
        if (!deviceInfo.manufacturerData(kManufacturerType).size() || deviceInfo.name() == "___YIoT___") {
            return;
        }

#if BLE_ENUM_DEBUG
        qDebug() << "[VIRGIL] Manufacturer Data : " << deviceInfo.manufacturerData(kManufacturerType);
#endif
        QString mac = deviceInfo.name();

        // Get name
        auto data = deviceInfo.manufacturerData(kManufacturerType);
        data.remove(0, 1);
        data.push_back('\0');
        auto name = QString::fromUtf8(data);

        // Create updated device info
        QBluetoothDeviceInfo fixedInfo(deviceInfo.address(), name, 0);
        fixedInfo.setRssi(deviceInfo.rssi());
        fixedInfo.setManufacturerData(kManufacturerType, deviceInfo.manufacturerData(kManufacturerType));
        fixedInfo.setCoreConfigurations(deviceInfo.coreConfigurations());
        fixedInfo.setDeviceUuid(deviceInfo.deviceUuid());
        fixedInfo.setServiceUuids(deviceInfo.serviceUuids().toVector());

        const bool _isInsert = !m_devices.keys().contains(mac);

        if (_isInsert) {
            // TODO: Fix it
            auto tmp = m_devices;
            tmp[mac] = BLEDevInfo();
            const int _pos = tmp.keys().indexOf(mac);
            beginInsertRows(QModelIndex(), _pos, _pos);
            m_devices[mac] = BLEDevInfo(fixedInfo, QDateTime::currentDateTime());
            endInsertRows();
        } else {
            auto oldRSSI = m_devices[mac].info.rssi();
            m_devices[mac].lastUpdate = QDateTime::currentDateTime();
            m_devices[mac].info = fixedInfo;
            if (oldRSSI && !fixedInfo.rssi()) {
                m_devices[mac].info.setRssi(oldRSSI);
            }
        }

        updateState(mac);
    }
}

/******************************************************************************/
void
VSQNetifBLEEnumerator::cleanOldDevices() {
    for (const auto &k : m_devices.keys()) {
        if (m_devices[k].lastUpdate.msecsTo(QDateTime::currentDateTime()) > kInactiveTimeoutMS) {
            const auto _pos = m_devices.keys().indexOf(k);
            beginRemoveRows(QModelIndex(), _pos, _pos);
            m_devices.remove(k);
            endRemoveRows();
        }
    }
}

/******************************************************************************/
void
VSQNetifBLEEnumerator::onDiscoveryFinished() {
    if (!QObject::sender())
        return;
    QObject::sender()->deleteLater();
    emit fireDiscoveryFinished();

    QTimer::singleShot(500, [this]() {
        if (!m_stopped) {
            startDiscovery();
        }
    });
}

/******************************************************************************/
void
VSQNetifBLEEnumerator::onDeviceUpdated(const QBluetoothDeviceInfo &info, QBluetoothDeviceInfo::Fields updatedFields) {
    auto mac = info.name();
    if (updatedFields.testFlag(QBluetoothDeviceInfo::Field::RSSI) && m_devices.keys().contains(mac)) {
        auto rssi = m_devices[mac].info.rssi();
        if (rssi != info.rssi()) {
            m_devices[mac].info.setRssi(info.rssi());
            updateState(mac);
        }
    }
}

/******************************************************************************/
void
VSQNetifBLEEnumerator::startDiscovery() {

    cleanOldDevices();

    // Create a discovery agent and connect to its signals
    QBluetoothDeviceDiscoveryAgent *discoveryAgent = new QBluetoothDeviceDiscoveryAgent(this);
    discoveryAgent->setLowEnergyDiscoveryTimeout(kBLEDiscoverPeriodMS);

    discoveryAgent->setInquiryType(QBluetoothDeviceDiscoveryAgent::LimitedInquiry);
    connect(discoveryAgent,
            &QBluetoothDeviceDiscoveryAgent::deviceDiscovered,
            this,
            &VSQNetifBLEEnumerator::onDeviceDiscovered);

    connect(discoveryAgent,
            &QBluetoothDeviceDiscoveryAgent::deviceUpdated,
            this,
            &VSQNetifBLEEnumerator::onDeviceUpdated);

    connect(discoveryAgent,
            &QBluetoothDeviceDiscoveryAgent::finished,
            this,
            &VSQNetifBLEEnumerator::onDiscoveryFinished);

    connect(discoveryAgent,
            &QBluetoothDeviceDiscoveryAgent::canceled,
            this,
            &VSQNetifBLEEnumerator::onDiscoveryFinished);

    connect(discoveryAgent, SIGNAL(error(QBluetoothDeviceDiscoveryAgent::Error)), this, SLOT(onDiscoveryFinished()));

    discoveryAgent->start(QBluetoothDeviceDiscoveryAgent::LowEnergyMethod);
}

/******************************************************************************/
void
VSQNetifBLEEnumerator::stopDiscovery() {
    m_stopped = true;
}

/******************************************************************************/
QBluetoothDeviceInfo
VSQNetifBLEEnumerator::devInfo(const QString &mac) const {
    if (m_devices.keys().contains(mac)) {
        return m_devices[mac].info;
    }

    return QBluetoothDeviceInfo();
}

/******************************************************************************/
int
VSQNetifBLEEnumerator::rowCount(const QModelIndex &parent) const {
    return m_devices.count();
}

/******************************************************************************/
int
VSQNetifBLEEnumerator::columnCount(const QModelIndex &parent) const {
    return 1;
}

/******************************************************************************/
QVariant
VSQNetifBLEEnumerator::data(const QModelIndex &index, int role) const {
    if (index.row() < m_devices.count()) {
        auto key = m_devices.keys().at(index.row());

        switch (role) {
        case Element::Mac:
            return key;

        case Element::Name:
            return m_devices[key].info.name();

        case Element::Manufacture:
            return "";

        case Element::RSSI:
            return m_devices[key].info.rssi();

        case Element::Initialized:
            return index.row() % 2;
        }
    }

    return QVariant();
}

/******************************************************************************/
QHash<int, QByteArray>
VSQNetifBLEEnumerator::roleNames() const {
    QHash<int, QByteArray> roles;
    roles[Mac] = "mac";
    roles[Name] = "name";
    roles[Manufacture] = "manufacture";
    roles[RSSI] = "rssi";
    roles[Initialized] = "initialized";
    return roles;
}

/******************************************************************************/
