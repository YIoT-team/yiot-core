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

#if SCRT_CLIENT

#include <virgil/iot/protocols/snap/generated/snap_cvt.h>
#include <private/snap-private.h>
#include <virgil/iot/protocols/snap/scrt/scrt-client.h>
#include <virgil/iot/protocols/snap/scrt/scrt-structs.h>
#include <virgil/iot/protocols/snap/scrt/scrt-private.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/session/session.h>
#include <virgil/iot/high-level/high-level-crypto.h>
#include <stdlib-config.h>
#include <global-hal.h>
#include <stdbool.h>
#include <string.h>

static vs_secmodule_impl_t *_secmodule = NULL;
static vs_snap_service_t _scrt_client = {0};
static vs_snap_scrt_client_service_t _scrt_impl = {};

/******************************************************************************/
vs_status_e
vs_snap_scrt_get_info(const vs_netif_t *netif, const vs_mac_addr_t *mac) {
    vs_status_e ret_code;
    CHECK_NOT_ZERO_RET(mac, VS_CODE_ERR_ZERO_ARGUMENT);

    // Send request
    STATUS_CHECK_RET(vs_snap_send_request(netif, mac, VS_SCRT_SERVICE_ID, VS_SCRT_INFO, NULL, 0),
                     "Cannot send request");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_snap_scrt_request_session_key(const vs_netif_t *netif, const vs_mac_addr_t *mac) {
    vs_status_e ret_code;
    uint8_t request_buf[VS_SCRT_CLIENT_REQUEST_MAX_SZ];
    vs_scrt_gsek_request_t *get_session_key_request = (vs_scrt_gsek_request_t *)request_buf;

    // Clean buffer
    VS_IOT_MEMSET(request_buf, 0, VS_SCRT_CLIENT_REQUEST_MAX_SZ);

    // Fill NONCE
    STATUS_CHECK_RET(_secmodule->random(get_session_key_request->nonce, SCRT_NONCE_SZ), "Cannot fill NONCE");

    // Fill own certificate
    vs_cert_t *own_cert = (vs_cert_t *)get_session_key_request->user_cert_and_sign;
    uint16_t buf_sz = VS_SCRT_CLIENT_REQUEST_MAX_SZ - sizeof(vs_scrt_gsek_request_t);
    STATUS_CHECK_RET(vs_provision_own_cert(own_cert, buf_sz), "Cannot get own certificate");
    uint16_t own_cert_sz;
    STATUS_CHECK_RET(vs_crypto_hl_cert_size(own_cert, &own_cert_sz), "Cannot get own cert size");

    // Fill signature
    vs_sign_t *sign = (vs_sign_t *)&get_session_key_request->user_cert_and_sign[own_cert_sz];
    uint16_t sign_sz;
    uint8_t *sign_data = request_buf;
    size_t sign_data_sz = sizeof(vs_scrt_gsek_request_t) + own_cert_sz;
    STATUS_CHECK_RET(vs_crypto_hl_sign(_secmodule, sign_data, sign_data_sz, sign, buf_sz, &sign_sz),
                     "Cannot sign request");

    // Send request
    uint16_t request_sz = sign_data_sz + sign_sz;
    STATUS_CHECK_RET(vs_snap_send_request(netif, mac, VS_SCRT_SERVICE_ID, VS_SCRT_GSEK, request_buf, request_sz),
                     "Cannot send request");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_snap_scrt_add_user(const vs_netif_t *netif,
                      const vs_mac_addr_t *mac,
                      vs_user_type_t user_type,
                      const char *user_name,
                      const vs_cert_t *user_cert) {
    vs_status_e ret_code;
    size_t new_user_name_sz;
    uint8_t request_buf[VS_SCRT_CLIENT_REQUEST_MAX_SZ];
    vs_scrt_ausr_request_t *add_user_request = (vs_scrt_ausr_request_t *)request_buf;

    // Check input parameters
    CHECK_NOT_ZERO_RET(user_cert, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(user_name && user_name[0], VS_CODE_ERR_INCORRECT_ARGUMENT);
    new_user_name_sz = strnlen(user_name, USER_NAME_SZ_MAX);
    CHECK_NOT_ZERO_RET(new_user_name_sz < USER_NAME_SZ_MAX, VS_CODE_ERR_INCORRECT_ARGUMENT);

    // Fill request
    VS_IOT_MEMSET(request_buf, 0, VS_SCRT_CLIENT_REQUEST_MAX_SZ);      // Clean
    add_user_request->user_type = user_type;                           // User type
    VS_IOT_STRCPY((char *)add_user_request->new_user_name, user_name); // Fill user name
                                                                       // Fill user certificate
    uint16_t user_cert_sz;
    STATUS_CHECK_RET(vs_crypto_hl_cert_size(user_cert, &user_cert_sz), "Cannot get cert size");
    VS_IOT_MEMCPY(add_user_request->certs_and_sign, user_cert, user_cert_sz);
    add_user_request->new_user_cert_sz = user_cert_sz;

    // Fill own certificate
    vs_cert_t *own_cert = (vs_cert_t *)&add_user_request->certs_and_sign[user_cert_sz];
    uint16_t buf_sz = VS_SCRT_CLIENT_REQUEST_MAX_SZ - sizeof(vs_scrt_ausr_request_t) - user_cert_sz;
    STATUS_CHECK_RET(vs_provision_own_cert(own_cert, buf_sz), "Cannot get own certificate");
    uint16_t own_cert_sz;
    STATUS_CHECK_RET(vs_crypto_hl_cert_size(own_cert, &own_cert_sz), "Cannot get own cert size");
    add_user_request->current_owner_cert_sz = own_cert_sz;

    // Fill signature
    vs_sign_t *sign = (vs_sign_t *)&add_user_request->certs_and_sign[user_cert_sz + own_cert_sz];
    uint16_t sign_sz;
    uint8_t *sign_data = request_buf;
    size_t sign_data_sz = sizeof(vs_scrt_ausr_request_t) + user_cert_sz + own_cert_sz;
    STATUS_CHECK_RET(vs_crypto_hl_sign(_secmodule, sign_data, sign_data_sz, sign, buf_sz, &sign_sz),
                     "Cannot sign request");

    // Send request
    uint16_t request_sz = sign_data_sz + sign_sz;
    STATUS_CHECK_RET(vs_snap_send_request(netif, mac, VS_SCRT_SERVICE_ID, VS_SCRT_AUSR, request_buf, request_sz),
                     "Cannot send request");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_snap_scrt_remove_user(const vs_netif_t *netif,
                         const vs_mac_addr_t *mac,
                         vs_user_type_t user_type,
                         const char *user_name) {
    vs_status_e ret_code;
    size_t user_name_sz;
    uint8_t request_buf[VS_SCRT_CLIENT_REQUEST_MAX_SZ];
    vs_scrt_rusr_request_t *rm_user_request = (vs_scrt_rusr_request_t *)request_buf;

    // Check input parameters
    CHECK_NOT_ZERO_RET(user_name && user_name[0], VS_CODE_ERR_INCORRECT_ARGUMENT);
    user_name_sz = strnlen(user_name, USER_NAME_SZ_MAX);
    CHECK_NOT_ZERO_RET(user_name_sz < USER_NAME_SZ_MAX, VS_CODE_ERR_INCORRECT_ARGUMENT);

    // Fill request
    VS_IOT_MEMSET(request_buf, 0, VS_SCRT_CLIENT_REQUEST_MAX_SZ);    // Clean
    rm_user_request->user_type = user_type;                          // User type
    VS_IOT_STRCPY((char *)rm_user_request->rm_user_name, user_name); // Fill user name

    // Fill own certificate
    vs_cert_t *own_cert = (vs_cert_t *)rm_user_request->current_owner_cert_and_sign;
    uint16_t buf_sz = VS_SCRT_CLIENT_REQUEST_MAX_SZ - sizeof(vs_scrt_rusr_request_t);
    STATUS_CHECK_RET(vs_provision_own_cert(own_cert, buf_sz), "Cannot get own certificate");
    uint16_t own_cert_sz;
    STATUS_CHECK_RET(vs_crypto_hl_cert_size(own_cert, &own_cert_sz), "Cannot get own cert size");

    // Fill signature
    vs_sign_t *sign = (vs_sign_t *)&rm_user_request->current_owner_cert_and_sign[own_cert_sz];
    uint16_t sign_sz;
    uint8_t *sign_data = request_buf;
    size_t sign_data_sz = sizeof(vs_scrt_ausr_request_t) + own_cert_sz;
    STATUS_CHECK_RET(vs_crypto_hl_sign(_secmodule, sign_data, sign_data_sz, sign, buf_sz, &sign_sz),
                     "Cannot sign request");

    // Send request
    uint16_t request_sz = sign_data_sz + sign_sz;
    STATUS_CHECK_RET(vs_snap_send_request(netif, mac, VS_SCRT_SERVICE_ID, VS_SCRT_RUSR, request_buf, request_sz),
                     "Cannot send request");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_snap_scrt_get_users(const vs_netif_t *netif,
                       const vs_mac_addr_t *mac,
                       vs_user_type_t user_type,
                       uint8_t offset,
                       uint8_t max_amount) {
#if 0
    vs_status_e ret_code;
    vs_scrt_gusr_request_t get_users_request;

    // Fill request
    VS_IOT_MEMSET(&get_users_request, 0, VS_SCRT_CLIENT_REQUEST_MAX_SZ); // Clean
    get_users_request.user_type = user_type;                             // User type
    get_users_request.max_users_per_resp = max_amount;                   // Maximum users in response
    get_users_request.users_offset = offset;                             // Offset of the first user in response

    // Send request
    STATUS_CHECK_RET(vs_snap_send_request(netif,
                                          mac,
                                          VS_SCRT_SERVICE_ID,
                                          VS_SCRT_GUSR,
                                          (uint8_t *)&get_users_request,
                                          sizeof(vs_scrt_gusr_request_t)),
                     "Cannot send request");
#endif
    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_session_key_processing(const struct vs_netif_t *netif,
                        const vs_ethernet_header_t *eth_header,
                        vs_snap_element_t element_id,
                        bool is_ack,
                        const uint8_t *response,
                        const uint16_t response_sz) {
    vs_status_e ret_code = VS_CODE_ERR_CRYPTO;
    vs_session_key_t *key = NULL;
    vs_snap_transaction_id_t id = 0;

    // Do not process data, because of error
    CHECK_NOT_ZERO(is_ack);

    // Process received data
    CHECK_NOT_ZERO(response);
    CHECK_NOT_ZERO(response_sz > sizeof(vs_scrt_gsek_response_t));
    vs_scrt_gsek_response_t *key_response = (vs_scrt_gsek_response_t *)response;

    // Verify request
    const vs_cert_t *sender_cert = (vs_cert_t *)key_response->device_cert_and_sign;
    uint16_t sender_cert_sz;
    STATUS_CHECK(vs_crypto_hl_cert_size(sender_cert, &sender_cert_sz), "Cannot get size of cert");
    const uint8_t *signed_data = response;
    const size_t signed_data_sz = sizeof(vs_scrt_gsek_response_t) + sender_cert_sz;
    const vs_sign_t *response_sign = (vs_sign_t *)&key_response->device_cert_and_sign[sender_cert_sz];
    const vs_pubkey_dated_t *request_required_signer = (vs_pubkey_dated_t *)sender_cert->raw_cert;
    STATUS_CHECK(vs_crypto_hl_verify(_secmodule, signed_data, signed_data_sz, response_sign, request_required_signer),
                 "Cannot verify response");

    // Check NONCE

    // Save Session Key
    STATUS_CHECK(vs_session_add_key(&key_response->session_key), "Cannot save session key");

    key = &key_response->session_key;
    ret_code = VS_CODE_OK;

terminate:
    // Callback to inform upper level
    if (_scrt_impl.scrt_client_session_key_cb) {
        _scrt_impl.scrt_client_session_key_cb(eth_header->src, id, ret_code, key);
    }

    return ret_code;
}
/******************************************************************************/
static vs_status_e
_scrt_service_response_processor(const struct vs_netif_t *netif,
                                 const vs_ethernet_header_t *eth_header,
                                 vs_snap_element_t element_id,
                                 bool is_ack,
                                 const uint8_t *response,
                                 const uint16_t response_sz) {
    vs_snap_transaction_id_t id = 0;
    vs_status_e res = is_ack ? VS_CODE_OK : VS_CODE_ERR_SNAP_UNKNOWN;

    switch (element_id) {

    case VS_SCRT_INFO:
        CHECK_NOT_ZERO_RET(response_sz > sizeof(vs_scrt_info_response_t), VS_CODE_ERR_TOO_SMALL_BUFFER);
        if (_scrt_impl.scrt_client_info_cb) {
            const vs_scrt_info_response_t *scrt_info = (vs_scrt_info_response_t *)response;
            _scrt_impl.scrt_client_info_cb(eth_header->src, id, res, scrt_info);
        }
        break;

    case VS_SCRT_GSEK:
        _session_key_processing(netif, eth_header, element_id, is_ack, response, response_sz);
        break;

    case VS_SCRT_AUSR:
        if (_scrt_impl.scrt_client_add_user_cb) {
            _scrt_impl.scrt_client_add_user_cb(eth_header->src, id, res);
        }
        break;

    case VS_SCRT_RUSR:
        if (_scrt_impl.scrt_client_remove_user_cb) {
            _scrt_impl.scrt_client_remove_user_cb(eth_header->src, id, res);
        }
        break;

    case VS_SCRT_GUSR:
        if (_scrt_impl.scrt_client_get_users_cb) {
            _scrt_impl.scrt_client_get_users_cb(eth_header->src, id, res);
        }
        break;

    default: {
    }
    }

    return VS_CODE_OK;
}

/******************************************************************************/
const vs_snap_service_t *
vs_snap_scrt_client(vs_secmodule_impl_t *secmodule, vs_snap_scrt_client_service_t impl) {

    CHECK_NOT_ZERO_RET(secmodule, NULL);

    _secmodule = secmodule;
    _scrt_client.user_data = 0;
    _scrt_client.id = VS_SCRT_SERVICE_ID;
    _scrt_client.request_process = NULL;
    _scrt_client.response_process = _scrt_service_response_processor;
    _scrt_client.periodical_process = NULL;

    _scrt_impl = impl;

    return &_scrt_client;
}

/******************************************************************************/

#endif // SCRT_CLIENT
