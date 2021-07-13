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

#ifndef VS_SECURITY_SDK_SNAP_SERVICES_SCRT_CLIENT_H
#define VS_SECURITY_SDK_SNAP_SERVICES_SCRT_CLIENT_H

#if SCRT_CLIENT

#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/protocols/snap/scrt/scrt-structs.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

#define VS_SCRT_CLIENT_REQUEST_MAX_SZ (768)


typedef vs_status_e (*vs_snap_scrt_client_info_cb_t)(vs_mac_addr_t mac,
                                                     vs_snap_transaction_id_t id,
                                                     vs_status_e res,
                                                     const vs_scrt_info_response_t *scrt_info);
typedef vs_status_e (*vs_snap_scrt_client_session_key_cb_t)(vs_mac_addr_t mac,
                                                            vs_snap_transaction_id_t id,
                                                            vs_status_e res,
                                                            const vs_session_key_t *key);
typedef vs_status_e (*vs_snap_scrt_client_add_user_cb_t)(vs_mac_addr_t mac,
                                                         vs_snap_transaction_id_t id,
                                                         vs_status_e res);
typedef vs_status_e (*vs_snap_scrt_client_remove_user_cb_t)(vs_mac_addr_t mac,
                                                            vs_snap_transaction_id_t id,
                                                            vs_status_e res);
typedef vs_status_e (*vs_snap_scrt_client_get_users_cb_t)(vs_mac_addr_t mac,
                                                          vs_snap_transaction_id_t id,
                                                          vs_status_e res);

/** SCRT client implementation */
typedef struct {
    vs_snap_scrt_client_info_cb_t scrt_client_info_cb;
    vs_snap_scrt_client_session_key_cb_t scrt_client_session_key_cb;
    vs_snap_scrt_client_add_user_cb_t scrt_client_add_user_cb;
    vs_snap_scrt_client_remove_user_cb_t scrt_client_remove_user_cb;
    vs_snap_scrt_client_get_users_cb_t scrt_client_get_users_cb;
} vs_snap_scrt_client_service_t;

const vs_snap_service_t *
vs_snap_scrt_client(vs_secmodule_impl_t *secmodule, vs_snap_scrt_client_service_t impl);

vs_status_e
vs_snap_scrt_get_info(const vs_netif_t *netif, const vs_mac_addr_t *mac);

vs_status_e
vs_snap_scrt_request_session_key(const vs_netif_t *netif, const vs_mac_addr_t *mac);

vs_status_e
vs_snap_scrt_add_user(const vs_netif_t *netif,
                      const vs_mac_addr_t *mac,
                      vs_user_type_t user_type,
                      const char *user_name,
                      const vs_cert_t *user_cert);

vs_status_e
vs_snap_scrt_remove_user(const vs_netif_t *netif,
                         const vs_mac_addr_t *mac,
                         vs_user_type_t user_type,
                         const char *user_name);

vs_status_e
vs_snap_scrt_get_users(const vs_netif_t *netif,
                       const vs_mac_addr_t *mac,
                       vs_user_type_t user_type,
                       uint8_t offset,
                       uint8_t max_amount);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // SCRT_CLIENT

#endif // VS_SECURITY_SDK_SNAP_SERVICES_SCRT_CLIENT_H
