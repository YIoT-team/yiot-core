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

#include <virgil/iot/qt/VSQIoTKit.h>

#include <cstdio>
#include <cstring>

using namespace VirgilIoTKit;

VSQSnapCfgClient::VSQSnapCfgClient() {
    vs_snap_cfg_client_service_t impl;
    memset(&impl, 0, sizeof(impl));
    impl.client_wifi_config_cb = &VSQSnapCfgClient::onConfigResult;
    m_snapService = vs_snap_cfg_client(impl);
}

vs_status_e
VSQSnapCfgClient::onConfigResult(vs_snap_transaction_id_t id, vs_status_e res) {
    Q_UNUSED(id)
    if (VS_CODE_OK == res) {
        emit VSQSnapCfgClient::instance().fireConfigurationDone();
    } else {
        emit VSQSnapCfgClient::instance().fireConfigurationError();
    }

    return VS_CODE_OK;
}

void
VSQSnapCfgClient::onConfigureDevice(QSharedPointer<VSQNetifBase> netif, VSQMac deviceMac) {
    qDebug() << "Configure ssid:<" << m_ssid << "> pass:<" << m_pass << ">";

    if (!m_ssid.length()) {
        VS_LOG_ERROR("SSID string is empty");
        return;
    }

    if (m_ssid.length() >= VS_CFG_STR_MAX) {
        VS_LOG_ERROR("SSID string is longer than %d", VS_CFG_STR_MAX);
        return;
    }

    if (!m_pass.length()) {
        VS_LOG_ERROR("Password string is empty");
        return;
    }

    if (m_pass.length() >= VS_CFG_STR_MAX) {
        VS_LOG_ERROR("Password string is longer than %d", VS_CFG_STR_MAX);
        return;
    }

    vs_cfg_wifi_configuration_t config;
    memset(&config, 0, sizeof(config));
    ::strcpy(reinterpret_cast<char *>(config.ssid), m_ssid.toStdString().c_str());
    ::strcpy(reinterpret_cast<char *>(config.pass), m_pass.toStdString().c_str());


    vs_mac_addr_t mac = deviceMac;
    if (VS_CODE_OK != vs_snap_cfg_wifi_configure_device(netif->lowLevelNetif(),
                                 &mac,
                                 &config)) {
        VS_LOG_ERROR("Cannot configure device");
    }
}

void
VSQSnapCfgClient::onSetConfigData(QString ssid, QString pass) {
    m_ssid = ssid;
    m_pass = pass;
}
