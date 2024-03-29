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

#include "stdlib-config.h"
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/macros/macros.h>
#include <private/snap-private.h>
#include <virgil/iot/protocols/snap/generated/snap_cvt.h>
#include <virgil/iot/session/session.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define VS_ENABLE_ROUTING (1)

static vs_netif_t *_netifs[VS_SNAP_NETIF_MAX];
static size_t _netifs_cnt = 0;

#define RESPONSE_SZ_MAX (1024 * 10)
#define RESPONSE_RESERVED_SZ (sizeof(vs_snap_packet_t))
#define SERVICES_CNT_MAX (10)

static const vs_snap_service_t *_snap_services[SERVICES_CNT_MAX];
static uint32_t _snap_services_num = 0;
static vs_mac_addr_t _snap_broadcast_mac = {.bytes = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};

static vs_snap_stat_t _statistics = {0, 0};

static vs_device_manufacture_id_t _manufacture_id;
static vs_device_type_t _device_type;
static vs_device_serial_t _device_serial;
static uint32_t _device_roles = 0; // See vs_snap_device_role_e
static char _device_name[DEVICE_NAME_SZ_MAX] = {0};

static vs_netif_process_cb_t _preprocessor_cb = NULL;
static vs_netif_need_enc_cb_t _need_enc_cb = NULL;
static vs_snap_name_cb_t _name_change_cb = NULL;

#define VS_SNAP_PROFILE 0

#if VS_SNAP_PROFILE
#include <sys/time.h>
static long long _processing_time = 0;
static long _calls_counter = 0;

/******************************************************************************/
static long long
current_timestamp() {
    struct timeval te;
    gettimeofday(&te, NULL);                               // get current time
    long long us = te.tv_sec * 1000LL + te.tv_usec / 1000; // calculate ms
    return us;
}
#endif

/******************************************************************************/
static vs_netif_t *
_default_netif(void) {
    VS_IOT_ASSERT(_netifs_cnt);
    return _netifs[0];
}

/******************************************************************************/
bool
vs_snap_is_broadcast(const vs_mac_addr_t *mac_addr) {
    return 0 == memcmp(mac_addr->bytes, _snap_broadcast_mac.bytes, ETH_ADDR_LEN);
}

/******************************************************************************/
static bool
_is_my_mac(const vs_netif_t *netif, const vs_mac_addr_t *mac_addr) {
    vs_mac_addr_t netif_mac_addr;
    netif->mac_addr(netif, &netif_mac_addr);

    return 0 == memcmp(mac_addr->bytes, netif_mac_addr.bytes, ETH_ADDR_LEN);
}

/******************************************************************************/
static bool
_accept_packet(const vs_netif_t *netif, const vs_mac_addr_t *src_mac, const vs_mac_addr_t *dest_mac) {
    bool dst_is_broadcast = vs_snap_is_broadcast(dest_mac);
    bool dst_is_my_mac = _is_my_mac(netif, dest_mac);
    bool src_is_my_mac = _is_my_mac(netif, src_mac);
    return !src_is_my_mac && (dst_is_broadcast || dst_is_my_mac);
}

/******************************************************************************/
static vs_status_e
_packet_encrypt(vs_snap_packet_t *packet) {
    vs_status_e ret_code;
    size_t new_sz;
    vs_session_id_t session_id;

    // Check input parameters
    CHECK_NOT_ZERO_RET(packet, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // Check if already encrypted
    if (packet->header.flags & VS_SNAP_FLAG_ENCYPTED) {
        VS_LOG_DEBUG("Packet already encrypted");
        return VS_CODE_OK;
    }

    // Prepare session ID
#if SCRT_SERVER
    vs_mac_addr_t mac;
    STATUS_CHECK_RET(vs_snap_mac_addr(0, &mac), "");
    VS_IOT_MEMCPY(session_id.prefix, mac.bytes, SESSION_ID_PREFIX_SZ);
#else
    VS_IOT_MEMCPY(session_id.prefix, packet->eth_header.dest.bytes, SESSION_ID_PREFIX_SZ);
#endif
    session_id.crc16 = 0;

    // Encrypt packet
    //      TODO: Pay attention to buffer size,
    //            because encrypted data is bigger than non-encrypted
    STATUS_CHECK_RET(vs_session_encrypt(&session_id, packet->content, packet->header.content_size, &new_sz), "");

    // Fill info about encrypted packet
    packet->header.flags |= VS_SNAP_FLAG_ENCYPTED;
    packet->header.content_size = new_sz;

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_packet_decrypt(vs_snap_packet_t *packet) {
    vs_status_e ret_code;
    size_t new_sz;
    vs_session_id_t session_id;

    // Check input parameters
    CHECK_NOT_ZERO_RET(packet, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // Check if encrypted
    if (!(packet->header.flags & VS_SNAP_FLAG_ENCYPTED)) {
        VS_LOG_DEBUG("Packet is not encrypted");
        return VS_CODE_OK;
    }

    // Prepare session ID
#if SCRT_SERVER
    vs_mac_addr_t mac;
    STATUS_CHECK_RET(vs_snap_mac_addr(0, &mac), "");
    VS_IOT_MEMCPY(session_id.prefix, mac.bytes, SESSION_ID_PREFIX_SZ);
#else
    VS_IOT_MEMCPY(session_id.prefix, packet->eth_header.src.bytes, SESSION_ID_PREFIX_SZ);
#endif
    session_id.crc16 = 0;

    // Decrypt packet
    STATUS_CHECK_RET(vs_session_decrypt(&session_id, packet->content, packet->header.content_size, &new_sz), "");

    // Fill info about decrypted packet
    packet->header.flags &= ~VS_SNAP_FLAG_ENCYPTED;
    packet->header.content_size = new_sz;

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_process_packet(const vs_netif_t *netif, vs_snap_packet_t *packet) {
    vs_status_e ret_code;
    uint32_t i;
    uint8_t response[RESPONSE_SZ_MAX + RESPONSE_RESERVED_SZ];
    uint16_t response_sz = 0;
    int res;
    vs_snap_packet_t *response_packet = (vs_snap_packet_t *)response;
    bool need_response = false;


    CHECK_NOT_ZERO_RET(_need_enc_cb, VS_CODE_ERR_NOT_FOUND);
    if (_need_enc_cb(packet->header.service_id, packet->header.element_id)) {
        if (!(packet->header.flags & VS_SNAP_FLAG_ENCYPTED)) {
            VS_LOG_WARNING("Command must be encrypted.");
            return VS_CODE_ERR_UNSUPPORTED;
        }
        VS_LOG_DEBUG("Decrypt packet ...");
        STATUS_CHECK_RET(_packet_decrypt(packet), "Cannot decrypt packet");
    }

    VS_IOT_MEMSET(response, 0, sizeof(response));

    // Prepare request
    VS_IOT_MEMCPY(&response_packet->header, &packet->header, sizeof(vs_snap_header_t));
    _snap_fill_header(&packet->eth_header.src, packet->header.transaction_id, response_packet);

    // Detect required command
    for (i = 0; i < _snap_services_num; i++) {
        if (_snap_services[i]->id == packet->header.service_id) {

            // Process response
            if (packet->header.flags & VS_SNAP_FLAG_ACK || packet->header.flags & VS_SNAP_FLAG_NACK) {
                if (_snap_services[i]->response_process) {
                    _snap_services[i]->response_process(netif,
                                                        &packet->eth_header,
                                                        packet->header.element_id,
                                                        !!(packet->header.flags & VS_SNAP_FLAG_ACK),
                                                        packet->content,
                                                        packet->header.content_size);
                }

                // Process request
            } else if (_snap_services[i]->request_process) {
                need_response = true;
                _statistics.received++;
                res = _snap_services[i]->request_process(netif,
                                                         &packet->eth_header,
                                                         packet->header.element_id,
                                                         packet->content,
                                                         packet->header.content_size,
                                                         response_packet->content,
                                                         RESPONSE_SZ_MAX,
                                                         &response_sz);
                if (VS_CODE_OK == res) {
                    // Send response
                    response_packet->header.content_size = response_sz;
                    response_packet->header.flags |= VS_SNAP_FLAG_ACK;
                } else {
                    if (VS_CODE_COMMAND_NO_RESPONSE == res) {
                        need_response = false;
                    } else {
                        // Send response with error code
                        // TODO: Fill structure with error code here
                        response_packet->header.flags |= VS_SNAP_FLAG_NACK;
                        response_packet->header.content_size = 0;
                    }
                }
            }
        }
    }

    if (need_response) {
        vs_snap_send(netif, response, sizeof(vs_snap_packet_t) + response_packet->header.content_size);
    }

    return VS_CODE_OK;
}

/******************************************************************************/
static uint16_t
_packet_sz(const uint8_t *packet_data) {
    const vs_snap_packet_t *packet = (vs_snap_packet_t *)packet_data;
    return sizeof(vs_snap_packet_t) + VS_IOT_NTOHS(packet->header.content_size);
}

/******************************************************************************/
static vs_status_e
_snap_periodical(void) {
    int i;
    // Detect required command
    for (i = 0; i < _snap_services_num; i++) {
        if (_snap_services[i]->periodical_process) {
            _snap_services[i]->periodical_process();
        }
    }

    return VS_CODE_OK;
}

/******************************************************************************/
#if VS_ENABLE_ROUTING
static bool
_need_routing(const vs_netif_t *netif, const vs_mac_addr_t *src_mac, const vs_mac_addr_t *dest_mac) {
    bool dst_is_broadcast = vs_snap_is_broadcast(dest_mac);
    bool dst_is_my_mac = _is_my_mac(netif, dest_mac);
    bool src_is_my_mac = _is_my_mac(netif, src_mac);
    return !src_is_my_mac && (dst_is_broadcast || !dst_is_my_mac);
}
#endif
/******************************************************************************/
static vs_status_e
_snap_rx_cb(vs_netif_t *netif,
            const uint8_t *data,
            const uint16_t data_sz,
            const uint8_t **packet_data,
            uint16_t *packet_data_sz) {
#define LEFT_INCOMING ((int)data_sz - bytes_processed)
    int bytes_processed = 0;
    int need_bytes_for_header;
    int need_bytes_for_packet;
    uint16_t packet_sz = 0;
    uint16_t copy_bytes;
#if VS_ENABLE_ROUTING
    size_t i;
#endif

    vs_snap_packet_t *packet = 0;

    while (LEFT_INCOMING) {

        if (!netif->packet_buf_filled) {
            if (LEFT_INCOMING >= sizeof(vs_snap_packet_t)) {
                packet_sz = _packet_sz(&data[bytes_processed]);

                if (LEFT_INCOMING < packet_sz) {
                    VS_IOT_MEMCPY(&netif->packet_buf[netif->packet_buf_filled], &data[bytes_processed], LEFT_INCOMING);
                    netif->packet_buf_filled += LEFT_INCOMING;
                    bytes_processed += LEFT_INCOMING;
                } else {
                    packet = (vs_snap_packet_t *)&data[bytes_processed];
                    bytes_processed += packet_sz;
                }
            } else {
                VS_IOT_MEMCPY(&netif->packet_buf[netif->packet_buf_filled], &data[bytes_processed], LEFT_INCOMING);
                netif->packet_buf_filled += LEFT_INCOMING;
                bytes_processed += LEFT_INCOMING;
            }

        } else {

            // Fill packet struct
            if (netif->packet_buf_filled < sizeof(vs_snap_packet_t)) {
                need_bytes_for_header = sizeof(vs_snap_packet_t) - netif->packet_buf_filled;

                copy_bytes = LEFT_INCOMING >= need_bytes_for_header ? need_bytes_for_header : LEFT_INCOMING;
                VS_IOT_MEMCPY(&netif->packet_buf[netif->packet_buf_filled], &data[bytes_processed], copy_bytes);
                bytes_processed += copy_bytes;
                netif->packet_buf_filled += copy_bytes;
            }

            // Fill content
            if (netif->packet_buf_filled >= sizeof(vs_snap_packet_t)) {
                packet_sz = _packet_sz(netif->packet_buf);

                need_bytes_for_packet = packet_sz - netif->packet_buf_filled;

                copy_bytes = LEFT_INCOMING >= need_bytes_for_packet ? need_bytes_for_packet : LEFT_INCOMING;
                VS_IOT_MEMCPY(&netif->packet_buf[netif->packet_buf_filled], &data[bytes_processed], copy_bytes);
                bytes_processed += copy_bytes;
                netif->packet_buf_filled += copy_bytes;

                if (netif->packet_buf_filled >= packet_sz) {
                    packet = (vs_snap_packet_t *)netif->packet_buf;
                }
            }
        }

        if (packet) {

            // Route incoming packet, if it's required and our role is Gateway
#if VS_ENABLE_ROUTING
            if (_device_roles & VS_SNAP_DEV_GATEWAY) {
                if (_need_routing(netif, &packet->eth_header.src, &packet->eth_header.dest)) {
                    for (i = 0; i < _netifs_cnt; i++) {
                        if (_netifs[i] && _netifs[i] != netif) {
                            _netifs[i]->tx(_netifs[i], (uint8_t *)packet, packet_sz);
                        }
                    }
                }
            }
#endif

            // Reset filled packet
            netif->packet_buf_filled = 0;
            // Normalize byte order
            vs_snap_packet_t_decode(packet);

            // Check is my packet
            if (_accept_packet(netif, &packet->eth_header.src, &packet->eth_header.dest)) {
                // Prepare for processing
                *packet_data = (uint8_t *)packet;
                *packet_data_sz = packet_sz;
                return VS_CODE_OK;
            }

            packet = 0;
        }
    }

    return VS_CODE_ERR_SNAP_UNKNOWN;
}

/******************************************************************************/
vs_status_e
vs_snap_default_processor(vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz) {
    vs_snap_packet_t *packet = (vs_snap_packet_t *)data;
    vs_status_e res;

#if VS_SNAP_PROFILE
    long long t;
    long long dt;
    _calls_counter++;
    t = current_timestamp();
#endif

    // TODO: To improve working with periodical timer
    if (!data && !data_sz) {
        _snap_periodical();
#if VS_SNAP_PROFILE
        _processing_time += current_timestamp() - t;
#endif
        return VS_CODE_OK;
    }

    VS_IOT_ASSERT(packet);
    res = _process_packet(netif, packet);
#if VS_SNAP_PROFILE
    dt = current_timestamp() - t;
    _processing_time += dt;
    VS_LOG_INFO("[_process_packet]. Time op = %lld ms Total time: %lld ms Calls: %ld",
                dt,
                _processing_time,
                _calls_counter);
#endif

    return res;
}

/******************************************************************************/
vs_status_e
vs_snap_init(vs_netif_t *default_netif,
             vs_netif_process_cb_t packet_preprocessor_cb,
             vs_netif_need_enc_cb_t need_enc_cb,
             vs_snap_name_cb_t name_change_cb,
             const vs_device_manufacture_id_t manufacturer_id,
             const vs_device_type_t device_type,
             const vs_device_serial_t device_serial,
             uint32_t device_roles) {

    // Check input data
    VS_IOT_ASSERT(default_netif);
    VS_IOT_ASSERT(default_netif->init);
    VS_IOT_ASSERT(default_netif->tx);
    VS_IOT_ASSERT(need_enc_cb);

    // Save device parameters
    VS_IOT_MEMCPY(_manufacture_id, manufacturer_id, sizeof(_manufacture_id));
    VS_IOT_MEMCPY(_device_type, device_type, sizeof(_device_type));
    VS_IOT_MEMCPY(_device_serial, device_serial, sizeof(_device_serial));

#if VS_SNAP_PROFILE
    vs_log_level_t log_level = vs_logger_get_loglev();
    if (VS_LOGLEV_UNKNOWN == log_level) {
        vs_logger_init(VS_LOGLEV_DEBUG);
    }
#endif

    // Set packet processor
    if (packet_preprocessor_cb) {
        _preprocessor_cb = packet_preprocessor_cb;
    } else {
        _preprocessor_cb = vs_snap_default_processor;
    }
    _name_change_cb = name_change_cb;
    _device_roles = device_roles;
    _need_enc_cb = need_enc_cb;

    // Save default network interface
    return vs_snap_netif_add(default_netif);
}

/******************************************************************************/
void
vs_snap_packet_dump(const char *title, const vs_snap_packet_t *packet) {
#if 0
    if (!packet) {
        return;
    }
    uint32_t sid = packet->header.service_id;
    const char *p = (char *)&sid;
    uint32_t eid = packet->header.element_id;
    const char *pe = (char *)&eid;
    VS_LOG_DEBUG("%s: %c%c%c%c:%c%c%c%c id: %u",
                 title ? title : "",
                 p[0],
                 p[1],
                 p[2],
                 p[3],
                 pe[0],
                 pe[1],
                 pe[2],
                 pe[3],
                 (unsigned int)packet->header.transaction_id);
#endif
}

/******************************************************************************/
vs_status_e
vs_snap_deinit() {
    int i;

    // Stop network
    for (i = 0; i < _netifs_cnt; i++) {
        if (_netifs[i]->deinit) {
            _netifs[i]->deinit(_netifs[i]);
        }
    }

    // Deinit all services
    for (i = 0; i < _snap_services_num; i++) {
        if (_snap_services[i]->deinit) {
            _snap_services[i]->deinit();
        }
    }

    // Clean services list
    _snap_services_num = 0;

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_snap_netif_add(vs_netif_t *netif) {
    VS_IOT_ASSERT(netif);
    VS_IOT_ASSERT(netif->init);
    VS_IOT_ASSERT(netif->tx);

    if (_netifs_cnt >= VS_SNAP_NETIF_MAX) {
        return VS_CODE_ERR_SNAP_TOO_MUCH_NETIFS;
    }

    _netifs[_netifs_cnt++] = netif;

    // Init network interface
    return netif->init(netif, _snap_rx_cb, _preprocessor_cb);
}

/******************************************************************************/
const vs_netif_t *
vs_snap_default_netif(void) {
    VS_IOT_ASSERT(_default_netif());
    return _default_netif();
}

/******************************************************************************/
const vs_netif_t *
vs_snap_netif_routing(void) {
    return (vs_netif_t *)1;
}

/******************************************************************************/
vs_status_e
vs_snap_send(const vs_netif_t *netif, const uint8_t *data, uint16_t data_sz) {
    vs_status_e ret_code;
    size_t i;
    uint16_t fixed_data_sz = data_sz;

    VS_IOT_ASSERT(_default_netif());
    VS_IOT_ASSERT(netif);

    vs_snap_packet_t *packet = (vs_snap_packet_t *)data;

    CHECK_NOT_ZERO_RET(_need_enc_cb, VS_CODE_ERR_NOT_FOUND);
    if (!(packet->header.flags & VS_SNAP_FLAG_ENCYPTED)) {
        if (_need_enc_cb(packet->header.service_id, packet->header.element_id)) {
            VS_LOG_DEBUG("Encrypt packet ...");
            STATUS_CHECK_RET(_packet_encrypt(packet), "Cannot encrypt message");
            fixed_data_sz = sizeof(vs_snap_packet_t) + packet->header.content_size;
        }
    }

    if (fixed_data_sz < sizeof(vs_snap_packet_t)) {
        return VS_CODE_ERR_INCORRECT_ARGUMENT;
    }

    // Normalize byte order
    if (packet) {
        vs_snap_packet_t_encode(packet);
    }

    // Is routing required ?
    if (netif == vs_snap_netif_routing()) {
        for (i = 0; i < _netifs_cnt; i++) {
            if (_netifs[i]) {
                _snap_set_src_mac(_netifs[i], (vs_snap_packet_t *)data);
                _netifs[i]->tx(_netifs[i], data, fixed_data_sz);
            }
        }

        return VS_CODE_OK;
    }

    // Send message to certain network interface
    _snap_set_src_mac(netif, (vs_snap_packet_t *)data);
    return netif->tx((vs_netif_t *)netif, data, fixed_data_sz);
}

/******************************************************************************/
vs_status_e
vs_snap_register_service(const vs_snap_service_t *service) {

    VS_IOT_ASSERT(service);

    CHECK_RET(_snap_services_num < SERVICES_CNT_MAX,
              VS_CODE_ERR_SNAP_TOO_MUCH_SERVICES,
              "SNAP services amount exceed maximum sllowed %d",
              SERVICES_CNT_MAX);

    _snap_services[_snap_services_num] = service;
    _snap_services_num++;

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_snap_mac_addr(const vs_netif_t *netif, vs_mac_addr_t *mac_addr) {
    VS_IOT_ASSERT(mac_addr);

    const vs_netif_t *netif_fixed = netif ? netif : _default_netif();

    VS_IOT_ASSERT(netif_fixed);
    VS_IOT_ASSERT(netif_fixed->mac_addr);
    netif_fixed->mac_addr(netif_fixed, mac_addr);
    return VS_CODE_OK;
}

/******************************************************************************/
vs_snap_transaction_id_t
_snap_transaction_id() {
    static vs_snap_transaction_id_t id = 0;

    return id++;
}

/******************************************************************************/
vs_status_e
_snap_fill_header(const vs_mac_addr_t *recipient_mac,
                  vs_snap_transaction_id_t transaction_id,
                  vs_snap_packet_t *packet) {

    VS_IOT_ASSERT(packet);

    // Ethernet packet type
    packet->eth_header.type = VS_ETHERTYPE_VIRGIL;

    // Fill own MAC address for a default net interface
    _snap_set_src_mac(0, packet);

    // Fill recipient MAC address
    if (!recipient_mac) {
        VS_IOT_MEMSET(packet->eth_header.dest.bytes, 0xFF, sizeof(vs_mac_addr_t));
    } else {
        VS_IOT_MEMCPY(packet->eth_header.dest.bytes, recipient_mac->bytes, sizeof(vs_mac_addr_t));
    }

    // Transaction ID
    packet->header.transaction_id = transaction_id;

    return VS_CODE_OK;
}

/******************************************************************************/
int
_snap_set_src_mac(const vs_netif_t *netif, vs_snap_packet_t *packet) {
    VS_IOT_ASSERT(packet);
    vs_snap_mac_addr(netif, &packet->eth_header.src);
    return VS_CODE_OK;
}

/******************************************************************************/
const vs_mac_addr_t *
vs_snap_broadcast_mac(void) {
    return &_snap_broadcast_mac;
}

/******************************************************************************/
static vs_status_e
_prepare_packet(vs_snap_packet_t *packet,
                const vs_mac_addr_t *mac,
                vs_snap_transaction_id_t transaction_id,
                vs_snap_service_id_t service_id,
                vs_snap_element_t element_id,
                bool is_request,
                bool is_ack,
                const uint8_t *data,
                uint16_t data_sz) {

    CHECK_NOT_ZERO_RET(mac, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(packet, VS_CODE_ERR_ZERO_ARGUMENT);

    // Prepare request
    packet->header.service_id = service_id;
    packet->header.element_id = element_id;
    packet->header.content_size = data_sz;
    if (data_sz) {
        VS_IOT_MEMCPY(packet->content, data, data_sz);
    }
    _snap_fill_header(mac, transaction_id, packet);

    // Fill response info, if required
    if (!is_request) {
        if (is_ack) {
            packet->header.flags |= VS_SNAP_FLAG_ACK;
        } else {
            packet->header.flags |= VS_SNAP_FLAG_NACK;
        }
    }

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_snap_send_request(const vs_netif_t *netif,
                     const vs_mac_addr_t *mac,
                     vs_snap_service_id_t service_id,
                     vs_snap_element_t element_id,
                     const uint8_t *data,
                     uint16_t data_sz) {

    uint8_t buffer[RESPONSE_SZ_MAX];
    vs_snap_packet_t *packet;

    VS_IOT_MEMSET(buffer, 0, sizeof(buffer));

    // Prepare pointers
    packet = (vs_snap_packet_t *)buffer;

    // Prepare request
    CHECK_RET(VS_CODE_OK ==
                      _prepare_packet(
                              packet, mac, _snap_transaction_id(), service_id, element_id, true, false, data, data_sz),
              VS_CODE_ERR_TX_SNAP,
              "Cannot prepare packet to send");

    // Send request
    _statistics.sent++;
    return vs_snap_send(netif, buffer, sizeof(vs_snap_packet_t) + packet->header.content_size);
}

/******************************************************************************/
vs_status_e
vs_snap_send_response(const vs_netif_t *netif,
                      const vs_mac_addr_t *mac,
                      vs_snap_transaction_id_t transaction_id,
                      vs_snap_service_id_t service_id,
                      vs_snap_element_t element_id,
                      bool is_ack,
                      const uint8_t *data,
                      uint16_t data_sz) {
    uint8_t buffer[RESPONSE_SZ_MAX];
    vs_snap_packet_t *packet;

    VS_IOT_MEMSET(buffer, 0, sizeof(buffer));

    // Prepare pointers
    packet = (vs_snap_packet_t *)buffer;

    // Prepare request
    CHECK_RET(VS_CODE_OK == _prepare_packet(
                                    packet, mac, transaction_id, service_id, element_id, false, is_ack, data, data_sz),
              VS_CODE_ERR_TX_SNAP,
              "Cannot prepare packet to send");

    // Send response
    return vs_snap_send(netif, buffer, sizeof(vs_snap_packet_t) + packet->header.content_size);
}

/******************************************************************************/
vs_snap_stat_t
vs_snap_get_statistics(void) {
    return _statistics;
}

/******************************************************************************/
const vs_device_manufacture_id_t *
vs_snap_device_manufacture(void) {
    return &_manufacture_id;
}

/******************************************************************************/
const vs_device_type_t *
vs_snap_device_type(void) {
    return &_device_type;
}

/******************************************************************************/
const vs_device_serial_t *
vs_snap_device_serial(void) {
    return &_device_serial;
}

/******************************************************************************/
uint32_t
vs_snap_device_roles(void) {
    return _device_roles;
}

/******************************************************************************/
const char *
vs_snap_device_name(void) {
    return (const char *)_device_name;
}

/******************************************************************************/
vs_status_e
vs_snap_init_device_name(const char *name, bool inform) {
    CHECK_NOT_ZERO_RET(name, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_RET(strnlen(name, DEVICE_NAME_SZ_MAX) < DEVICE_NAME_SZ_MAX,
              VS_CODE_ERR_INCORRECT_PARAMETER,
              "Device name size is greater than 63 symbols.");

    VS_IOT_MEMSET(_device_name, 0, DEVICE_NAME_SZ_MAX);
    strcpy(_device_name, name);

    if (_name_change_cb && inform) {
        _name_change_cb();
    }

    return VS_CODE_OK;
}

/******************************************************************************/
