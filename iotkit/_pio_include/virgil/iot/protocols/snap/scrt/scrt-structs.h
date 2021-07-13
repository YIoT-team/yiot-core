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


#ifndef VS_SECURITY_SDK_SNAP_SERVICES_SCRT_STRUCTS_H
#define VS_SECURITY_SDK_SNAP_SERVICES_SCRT_STRUCTS_H

#include <virgil/iot/protocols/snap/snap-structs.h>
#include <virgil/iot/users/users-structs.h>
#include <virgil/iot/session/session-structs.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

#define SCRT_NONCE_SZ (32)


// --------------------------------------------------------
//      SCRT::INFO - Get crypto information
// --------------------------------------------------------
// INFO: Could be sent in a plain text
typedef struct __attribute__((__packed__)) {
    uint8_t provisioned;  /**< Device has provision */
    uint8_t owners_count; /**< Device has owners */
    vs_cert_t own_cert;   /**< Peer key and its signature */
} vs_scrt_info_response_t;

// --------------------------------------------------------
//      SCRT::GSEK - Get SEssion Key
// --------------------------------------------------------
// INFO: Must be encrypted asymmetrically
typedef struct __attribute__((__packed__)) {
    uint8_t nonce[SCRT_NONCE_SZ]; /**< nonce to protect against reply attacks */
    uint8_t user_cert_and_sign[]; /**< vs_cert_t and data signature*/
} vs_scrt_gsek_request_t;

// INFO: Must be encrypted asymmetrically
typedef struct __attribute__((__packed__)) {
    uint8_t requested_nonce[SCRT_NONCE_SZ]; /**< a copy of nonce from request */
    vs_session_key_t session_key;           /**< Session key. The simplest solution for ver.1 */
    uint8_t device_cert_and_sign[];         /**< vs_provision_cert_t and data signature*/
} vs_scrt_gsek_response_t;

// --------------------------------------------------------
//      SCRT::AUSR - Add a new User
// --------------------------------------------------------
// INFO: Must be encrypted asymmetrically
typedef struct __attribute__((__packed__)) {
    uint8_t user_type;                       /**< #vs_user_type_t */
    uint8_t new_user_name[USER_NAME_SZ_MAX]; /**< New User name */
    uint16_t new_user_cert_sz;               /**< Size of vs_provision_cert_t for new user */
    uint16_t current_owner_cert_sz;          /**< Size of vs_provision_cert_t for current owner */
    uint8_t certs_and_sign[]; /**< vs_provision_cert_t of a New and a current owners + vs_sign_t of data */
} vs_scrt_ausr_request_t;

// --------------------------------------------------------
//      SCRT::RUSR - Remove user
// --------------------------------------------------------
// INFO: Must be encrypted asymmetrically
typedef struct __attribute__((__packed__)) {
    uint8_t user_type;                      /**< #vs_user_type_t */
    uint8_t rm_user_name[USER_NAME_SZ_MAX]; /**< Name of User to be removed */
    uint8_t current_owner_cert_and_sign[];  /**< Current owner's vs_provision_cert_t + vs_sign_t of data */
} vs_scrt_rusr_request_t;

// --------------------------------------------------------
//      SCRT::GUSR - Get users
// --------------------------------------------------------
typedef struct __attribute__((__packed__)) {
    uint8_t user_name[USER_NAME_SZ_MAX]; /**< New name */
    vs_pubkey_dated_t user_pub_key;      /**< Public key of user */
} vs_scrt_gusr_tiny_t;

// INFO: Could be sent in a plain text
typedef struct __attribute__((__packed__)) {
    uint8_t user_type;          /**< #vs_user_type_t */
    uint8_t max_users_per_resp; /**< Maximum users in response */
    uint8_t users_offset;       /**< First user num to get */
} vs_scrt_gusr_request_t;

// INFO: Could be sent in a plain text
typedef struct __attribute__((__packed__)) {
    uint8_t user_type;     /**< #vs_user_type_t */
    uint8_t users_in_resp; /**< Amount of users in response */
    uint8_t users_offset;  /**< First user num */
    uint8_t users[];       /**< Array of #vs_scrt_gusr_tiny_t. Amount is #users_in_resp */
} vs_scrt_gusr_response_t;

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_SECURITY_SDK_SNAP_SERVICES_SCRT_STRUCTS_H
