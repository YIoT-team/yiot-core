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

#if CFG_CLIENT

#include <virgil/iot/protocols/snap/cfg/cfg-client.h>
#include <virgil/iot/protocols/snap/cfg/cfg-private.h>
#include <virgil/iot/protocols/snap/generated/snap_cvt.h>
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/logger/logger.h>
#include <stdlib-config.h>
#include <global-hal.h>

// External functions for access to upper level implementations
static vs_snap_service_t _cfg_client = {0};
static vs_snap_cfg_client_service_t _impl = {0};

/******************************************************************************/
vs_status_e
vs_snap_cfg_wifi_configure_device(const vs_netif_t *netif,
                                  const vs_mac_addr_t *mac,
                                  const vs_cfg_wifi_configuration_t *config) {
    vs_cfg_conf_wifi_request_t request;
    const vs_mac_addr_t *dst_mac;
    vs_status_e ret_code;

    // Check input parameters
    CHECK_NOT_ZERO_RET(config, VS_CODE_ERR_INCORRECT_ARGUMENT);

    // Set destination mac
    dst_mac = mac ? mac : vs_snap_broadcast_mac();

    // Fill request fields
    VS_IOT_MEMCPY(request.ssid, config->ssid, VS_CFG_STR_MAX);
    VS_IOT_MEMCPY(request.pass, config->pass, VS_CFG_STR_MAX);
    VS_IOT_MEMCPY(request.account, config->account, VS_CFG_STR_MAX);

    // Send request
    STATUS_CHECK_RET(
            vs_snap_send_request(netif, dst_mac, VS_CFG_SERVICE_ID, VS_CFG_WIFI, (uint8_t *)&request, sizeof(request)),
            "Cannot send request");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_snap_cfg_messenger_configure_device(const vs_netif_t *netif,
                                       const vs_mac_addr_t *mac,
                                       const vs_cfg_messenger_config_t *config) {
    const vs_mac_addr_t *dst_mac;
    vs_status_e ret_code;
    vs_cfg_messenger_config_request_t request;

    // Check input parameters
    CHECK_NOT_ZERO_RET(config, VS_CODE_ERR_INCORRECT_ARGUMENT);

    // Set destination mac
    dst_mac = mac ? mac : vs_snap_broadcast_mac();

    request.enjabberd_port = config->enjabberd_port;
    request.version = config->version;
    VS_IOT_MEMCPY(request.messenger_base_url, config->messenger_base_url, VS_HOST_NAME_MAX_SZ);
    VS_IOT_MEMCPY(request.enjabberd_host, config->enjabberd_host, VS_HOST_NAME_MAX_SZ);

    // Normalize byte order
    vs_cfg_messenger_config_request_t_encode(&request);

    // Send request
    STATUS_CHECK_RET(
            vs_snap_send_request(netif, dst_mac, VS_CFG_SERVICE_ID, VS_CFG_MSCR, (uint8_t *)&request, sizeof(request)),
            "Cannot send request");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_snap_cfg_channels_configure_device(const vs_netif_t *netif,
                                      const vs_mac_addr_t *mac,
                                      const vs_cfg_messenger_channels_t *config) {
    const vs_mac_addr_t *dst_mac;
    vs_status_e ret_code;
    uint8_t i;
    vs_cfg_messenger_channels_request_t request;

    // Check input parameters
    CHECK_NOT_ZERO_RET(config, VS_CODE_ERR_INCORRECT_ARGUMENT);

    // Set destination mac
    dst_mac = mac ? mac : vs_snap_broadcast_mac();

    request.channels_num = config->channels_num;
    for (i = 0; i < VS_MESSENGER_CHANNEL_NUM_MAX; ++i) {
        VS_IOT_MEMCPY(request.channel[i], config->channel[i], VS_MESSENGER_CHANNEL_MAX_SZ);
    }

    // Send request
    STATUS_CHECK_RET(
            vs_snap_send_request(netif, dst_mac, VS_CFG_SERVICE_ID, VS_CFG_MSCH, (uint8_t *)&request, sizeof(request)),
            "Cannot send request");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_snap_cfg_user_configure_device(const vs_netif_t *netif, const vs_mac_addr_t *mac, const vs_cfg_user_t *config) {
    const vs_mac_addr_t *dst_mac;
    vs_status_e ret_code;
    vs_cfg_user_config_request_t *request;

    // Check input parameters
    CHECK_NOT_ZERO_RET(config, VS_CODE_ERR_INCORRECT_ARGUMENT);

    // Set destination mac
    dst_mac = mac ? mac : vs_snap_broadcast_mac();

    uint32_t request_sz = config->data_sz + sizeof(vs_cfg_user_config_request_t);
    uint8_t buf[request_sz];
    request = (vs_cfg_user_config_request_t *)buf;
    request->data_type = config->data_type;
    request->data_sz = config->data_sz;
    VS_IOT_MEMCPY(request->data, config->data, config->data_sz);

    // Normalize byte order
    vs_cfg_user_config_request_t_encode(request);

    // Send request
    STATUS_CHECK_RET(vs_snap_send_request(netif, dst_mac, VS_CFG_SERVICE_ID, VS_CFG_USER, buf, request_sz),
                     "Cannot send request");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_snap_cfg_reset_device(const vs_netif_t *netif, const vs_mac_addr_t *mac) {
    vs_status_e ret_code;

    // Check input parameters
    CHECK_NOT_ZERO_RET(mac, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(!vs_snap_is_broadcast(mac), VS_CODE_ERR_INCORRECT_ARGUMENT);

    // Send request
    STATUS_CHECK_RET(vs_snap_send_request(netif, mac, VS_CFG_SERVICE_ID, VS_CFG_RSET, NULL, 0), "Cannot send request");

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_conf_response_processor(vs_snap_element_t element_id,
                         bool is_ack,
                         const uint8_t *response,
                         const uint16_t response_sz) {

    vs_snap_transaction_id_t id = 0;
    vs_status_e res = is_ack ? VS_CODE_OK : VS_CODE_ERR_SNAP_UNKNOWN;

    switch (element_id) {

    case VS_CFG_MSCR:
        if (_impl.client_messenger_config_cb) {
            _impl.client_messenger_config_cb(id, res);
        }
        break;

    case VS_CFG_MSCH:
        if (_impl.client_channel_config_cb) {
            _impl.client_channel_config_cb(id, res);
        }
        break;

    case VS_CFG_WIFI:
        if (_impl.client_wifi_config_cb) {
            _impl.client_wifi_config_cb(id, res);
        }
        break;

    case VS_CFG_USER:
        if (_impl.client_user_config_cb) {
            _impl.client_user_config_cb(id, res);
        }

    default: {
    }
    }

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_cfg_client_response_processor(const struct vs_netif_t *netif,
                               const vs_ethernet_header_t *eth_header,
                               vs_snap_element_t element_id,
                               bool is_ack,
                               const uint8_t *response,
                               const uint16_t response_sz) {
    (void)netif;

    switch (element_id) {

    case VS_CFG_MSCR:
    case VS_CFG_MSCH:
    case VS_CFG_WIFI:
    case VS_CFG_USER:
        return _conf_response_processor(element_id, is_ack, response, response_sz);

    default:
        VS_LOG_ERROR("Unsupported _CFG command");
        VS_IOT_ASSERT(false);
        return VS_CODE_COMMAND_NO_RESPONSE;
    }
}

/******************************************************************************/
const vs_snap_service_t *
vs_snap_cfg_client(vs_snap_cfg_client_service_t impl) {

    _cfg_client.user_data = 0;
    _cfg_client.id = VS_CFG_SERVICE_ID;
    _cfg_client.request_process = NULL;
    _cfg_client.response_process = _cfg_client_response_processor;
    _cfg_client.periodical_process = NULL;

    // Save callbacks
    VS_IOT_MEMCPY(&_impl, &impl, sizeof(impl));

    return &_cfg_client;
}

/******************************************************************************/

#endif // CFG_CLIENT
