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


#ifndef VS_SECURITY_SDK_SNAP_SERVICES_CFG_CLIENT_H
#define VS_SECURITY_SDK_SNAP_SERVICES_CFG_CLIENT_H

#if CFG_CLIENT

#include <virgil/iot/protocols/snap/cfg/cfg-structs.h>
#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/status_code/status_code.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

typedef vs_status_e (*vs_snap_cfg_client_wifi_cb_t)(vs_snap_transaction_id_t id, vs_status_e res);
typedef vs_status_e (*vs_snap_cfg_client_messenger_cb_t)(vs_snap_transaction_id_t id, vs_status_e res);
typedef vs_status_e (*vs_snap_cfg_client_channel_cb_t)(vs_snap_transaction_id_t id, vs_status_e res);
typedef vs_status_e (*vs_snap_cfg_client_user_cb_t)(vs_snap_transaction_id_t id, vs_status_e res);

typedef struct {
    vs_snap_cfg_client_wifi_cb_t client_wifi_config_cb;
    vs_snap_cfg_client_messenger_cb_t client_messenger_config_cb;
    vs_snap_cfg_client_channel_cb_t client_channel_config_cb;
    vs_snap_cfg_client_user_cb_t client_user_config_cb;
} vs_snap_cfg_client_service_t;

const vs_snap_service_t *
vs_snap_cfg_client(vs_snap_cfg_client_service_t impl);

vs_status_e
vs_snap_cfg_wifi_configure_device(const vs_netif_t *netif,
                                  const vs_mac_addr_t *mac,
                                  const vs_cfg_wifi_configuration_t *config);

vs_status_e
vs_snap_cfg_reset_device(const vs_netif_t *netif, const vs_mac_addr_t *mac);

vs_status_e
vs_snap_cfg_messenger_configure_device(const vs_netif_t *netif,
                                       const vs_mac_addr_t *mac,
                                       const vs_cfg_messenger_config_t *config);
vs_status_e
vs_snap_cfg_channels_configure_device(const vs_netif_t *netif,
                                      const vs_mac_addr_t *mac,
                                      const vs_cfg_messenger_channels_t *config);
vs_status_e
vs_snap_cfg_user_configure_device(const vs_netif_t *netif, const vs_mac_addr_t *mac, const vs_cfg_user_t *config);
#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // CFG_CLIENT

#endif // VS_SECURITY_SDK_SNAP_SERVICES_CFG_CLIENT_H
