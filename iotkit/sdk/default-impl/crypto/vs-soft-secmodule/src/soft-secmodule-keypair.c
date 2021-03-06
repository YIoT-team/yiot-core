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

#include <assert.h>
#include <stdint.h>

#include "private/vs-soft-secmodule-internal.h"

#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/converters/crypto_format_converters.h>

#include <mbedtls/pk_internal.h>
#include <mbedtls/oid.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#if !defined(SOFT_SECMODULE_EXTRA_DEBUG)
#define SOFT_SECMODULE_EXTRA_DEBUG 0
#endif

typedef struct __attribute__((__packed__)) {
    vs_secmodule_keypair_type_e keypair_type;
    uint16_t private_key_sz;
    uint16_t public_key_sz;
    uint8_t data[];
} keypair_storage_data;

/******************************************************************************/
static vs_status_e
_keypair_create_mbedtls(mbedtls_fast_ec_type_t fast_ec_type,
                        mbedtls_ecp_group_id key_type_mbedtls,
                        uint8_t *public_key,
                        uint16_t pubkey_buf_sz,
                        uint16_t *public_key_sz,
                        uint8_t *private_key,
                        uint16_t prvkey_buf_sz,
                        uint16_t *private_key_sz) {
    vs_status_e res = VS_CODE_ERR_CRYPTO;
    const char *pers = "gen_keypair";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk_ctx;
    int res_sz;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk_ctx);

    if (0 == mbedtls_ctr_drbg_seed(
                     &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, VS_IOT_STRLEN(pers))) {

        bool fl_keypair_ready = false;

        if (MBEDTLS_ECP_DP_NONE != key_type_mbedtls) {
            // EC except 25519 curves
            mbedtls_pk_setup(&pk_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
            fl_keypair_ready =
                    (0 ==
                     mbedtls_ecp_gen_key(key_type_mbedtls, mbedtls_pk_ec(pk_ctx), mbedtls_ctr_drbg_random, &ctr_drbg));
        } else if (MBEDTLS_FAST_EC_NONE != fast_ec_type) {
            mbedtls_pk_setup(&pk_ctx, mbedtls_pk_info_from_type(mbedtls_pk_from_fast_ec_type(fast_ec_type)));
            if (0 == mbedtls_fast_ec_setup(mbedtls_pk_fast_ec(pk_ctx), mbedtls_fast_ec_info_from_type(fast_ec_type)) &&
                0 == mbedtls_fast_ec_gen_key(mbedtls_pk_fast_ec(pk_ctx), mbedtls_ctr_drbg_random, &ctr_drbg)) {
                fl_keypair_ready = true;
            }
        }

        if (fl_keypair_ready) {
            res_sz = mbedtls_pk_write_pubkey_der(&pk_ctx, public_key, pubkey_buf_sz);
            if (res_sz > 0) {
                if (pubkey_buf_sz > res_sz) {
                    memmove(public_key, &public_key[pubkey_buf_sz - res_sz], res_sz);
                }
                *public_key_sz = res_sz;

                res_sz = mbedtls_pk_write_key_der(&pk_ctx, private_key, prvkey_buf_sz);

                if (res_sz > 0) {
                    if (prvkey_buf_sz > res_sz) {
                        memmove(private_key, &private_key[prvkey_buf_sz - res_sz], res_sz);
                    }
                    *private_key_sz = res_sz;

                    res = VS_CODE_OK;
                }
            }
        }
    }

    mbedtls_pk_free(&pk_ctx);

    return res;
}

/******************************************************************************/
vs_status_e
_keypair_create_internal(vs_secmodule_keypair_type_e keypair_type,
                         uint8_t *public_key,
                         uint16_t pubkey_buf_sz,
                         uint16_t *public_key_sz,
                         uint8_t *private_key,
                         uint16_t prvkey_buf_sz,
                         uint16_t *private_key_sz) {

    mbedtls_fast_ec_type_t fast_ec_type = MBEDTLS_FAST_EC_NONE;
    mbedtls_ecp_group_id key_type_mbedtls;

    switch (keypair_type) {

    case VS_KEYPAIR_EC_SECP192R1:
        key_type_mbedtls = MBEDTLS_ECP_DP_SECP192R1;
        break;

    case VS_KEYPAIR_EC_SECP224R1:
        key_type_mbedtls = MBEDTLS_ECP_DP_SECP224R1;
        break;

    case VS_KEYPAIR_EC_SECP256R1:
        key_type_mbedtls = MBEDTLS_ECP_DP_SECP256R1;
        break;

    case VS_KEYPAIR_EC_SECP384R1:
        key_type_mbedtls = MBEDTLS_ECP_DP_SECP384R1;
        break;

    case VS_KEYPAIR_EC_SECP521R1:
        key_type_mbedtls = MBEDTLS_ECP_DP_SECP521R1;
        break;

    case VS_KEYPAIR_EC_SECP192K1:
        key_type_mbedtls = MBEDTLS_ECP_DP_SECP192K1;
        break;

    case VS_KEYPAIR_EC_SECP224K1:
        key_type_mbedtls = MBEDTLS_ECP_DP_SECP224K1;
        break;

    case VS_KEYPAIR_EC_SECP256K1:
        key_type_mbedtls = MBEDTLS_ECP_DP_SECP256K1;
        break;

    case VS_KEYPAIR_EC_CURVE25519:
        fast_ec_type = MBEDTLS_FAST_EC_X25519;
        key_type_mbedtls = MBEDTLS_ECP_DP_NONE;
        break;

    case VS_KEYPAIR_EC_ED25519:
        fast_ec_type = MBEDTLS_FAST_EC_ED25519;
        key_type_mbedtls = MBEDTLS_ECP_DP_NONE;
        break;
    default:
        return VS_CODE_ERR_NOT_IMPLEMENTED;
    }

    return _keypair_create_mbedtls(fast_ec_type,
                                   key_type_mbedtls,
                                   public_key,
                                   pubkey_buf_sz,
                                   public_key_sz,
                                   private_key,
                                   prvkey_buf_sz,
                                   private_key_sz);
}

/********************************************************************************/
vs_status_e
vs_secmodule_keypair_create(vs_iot_secmodule_slot_e slot, vs_secmodule_keypair_type_e keypair_type) {
    vs_status_e ret_code;
    int32_t slot_sz = _get_slot_size(slot);
    const vs_secmodule_impl_t *_secmodule = _soft_secmodule_intern();

    CHECK_NOT_ZERO_RET(_secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_RET(slot_sz > 0, VS_CODE_ERR_INCORRECT_PARAMETER, "Incorrect slot number");

    uint8_t buf[slot_sz];
    keypair_storage_data *keypair_storage = (keypair_storage_data *)buf;
    uint8_t public_key[MAX_INTERNAL_PUBKEY_SIZE];
    uint16_t public_key_sz;
    uint16_t private_key_sz;
    uint16_t storage_data_sz;

    STATUS_CHECK_RET(_keypair_create_internal(keypair_type,
                                              public_key,
                                              sizeof(public_key),
                                              &public_key_sz,
                                              keypair_storage->data,
                                              slot_sz - sizeof(keypair_storage_data),
                                              &private_key_sz),
                     "Unable to create keypair");

    keypair_storage->keypair_type = keypair_type;
    keypair_storage->private_key_sz = (uint16_t)private_key_sz;

    CHECK_RET(vs_converters_pubkey_to_raw(keypair_type,
                                          public_key,
                                          public_key_sz,
                                          keypair_storage->data + private_key_sz,
                                          slot_sz - sizeof(keypair_storage_data) - private_key_sz,
                                          &public_key_sz),
              VS_CODE_ERR_CRYPTO,
              "Unable to convert a public key to raw");
    keypair_storage->public_key_sz = (uint16_t)public_key_sz;

    storage_data_sz = sizeof(keypair_storage_data) + keypair_storage->public_key_sz + keypair_storage->private_key_sz;


    STATUS_CHECK_RET(_secmodule->slot_save(slot, buf, storage_data_sz),
                     "Unable to save keypair buffer to the slot %s",
                     _get_slot_name(slot));

    return VS_CODE_OK;
}

/********************************************************************************/
vs_status_e
vs_secmodule_keypair_set(vs_iot_secmodule_slot_e slot,
                         vs_secmodule_keypair_type_e keypair_type,
                         const uint8_t *private_key,
                         uint16_t private_key_sz,
                         const uint8_t *public_key,
                         uint16_t public_key_sz) {
    vs_status_e ret_code;
    int32_t slot_sz = _get_slot_size(slot);
    const vs_secmodule_impl_t *_secmodule = _soft_secmodule_intern();

    const size_t required_slot_sz = private_key_sz + public_key_sz + sizeof(keypair_storage_data);

    CHECK_NOT_ZERO_RET(_secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(private_key, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(private_key_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_RET(slot_sz > 0, VS_CODE_ERR_INCORRECT_PARAMETER, "Incorrect slot number");
    CHECK_RET(slot_sz > required_slot_sz, VS_CODE_ERR_INCORRECT_PARAMETER, "Slot size too small");

    uint8_t buf[slot_sz];
    keypair_storage_data *keypair_storage = (keypair_storage_data *)buf;

    keypair_storage->keypair_type = keypair_type;
    keypair_storage->private_key_sz = (uint16_t)private_key_sz;
    keypair_storage->public_key_sz = (uint16_t)public_key_sz;

    VS_IOT_MEMCPY(keypair_storage->data, private_key, private_key_sz);
    if (public_key) {
        VS_IOT_MEMCPY(keypair_storage->data + private_key_sz, public_key, public_key_sz);
    }

    STATUS_CHECK_RET(_secmodule->slot_save(slot, buf, required_slot_sz),
                     "Unable to save keypair buffer to the slot %s",
                     _get_slot_name(slot));

    return VS_CODE_OK;
}

/********************************************************************************/
vs_status_e
vs_secmodule_keypair_get_pubkey(vs_iot_secmodule_slot_e slot,
                                uint8_t *buf,
                                uint16_t buf_sz,
                                uint16_t *key_sz,
                                vs_secmodule_keypair_type_e *keypair_type) {
    vs_status_e ret_code;
    int32_t slot_sz = _get_slot_size(slot);
    const vs_secmodule_impl_t *_secmodule = _soft_secmodule_intern();
    uint8_t *pubkey = NULL;

    CHECK_NOT_ZERO_RET(_secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(keypair_type, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(buf, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(key_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    uint8_t keypair_buf[slot_sz];
    keypair_storage_data *keypair_storage = (keypair_storage_data *)keypair_buf;
    uint16_t data_sz;

    STATUS_CHECK_RET(_secmodule->slot_load(slot, keypair_buf, slot_sz, &data_sz),
                     "Unable to load data from slot %d (%s)",
                     slot,
                     _get_slot_name(slot));
    *keypair_type = keypair_storage->keypair_type;

    ret_code = VS_CODE_ERR_CRYPTO;

    CHECK(keypair_storage->public_key_sz != 0, "Zero size public key");
    CHECK(keypair_storage->public_key_sz <= buf_sz,
          "Too big public key size %d bytes for buffer %d bytes",
          keypair_storage->public_key_sz,
          buf_sz);

    *key_sz = keypair_storage->public_key_sz;
    pubkey = keypair_storage->data + keypair_storage->private_key_sz;

    memcpy(buf, pubkey, *key_sz);

#if SOFT_SECMODULE_EXTRA_DEBUG
    VS_LOG_DEBUG("Public key %d bytes from slot %s with keypair type %s has been loaded",
                 *key_sz,
                 _get_slot_name(slot),
                 vs_secmodule_keypair_type_descr(*keypair_type));
#endif

    ret_code = VS_CODE_OK;

terminate:

    return ret_code;
}

/********************************************************************************/
vs_status_e
vs_secmodule_keypair_get_prvkey(vs_iot_secmodule_slot_e slot,
                                uint8_t *buf,
                                uint16_t buf_sz,
                                uint16_t *key_sz,
                                vs_secmodule_keypair_type_e *keypair_type) {
    vs_status_e ret_code;
    int32_t slot_sz = _get_slot_size(slot);
    const vs_secmodule_impl_t *_secmodule = _soft_secmodule_intern();

    CHECK_RET(slot_sz > 0, VS_CODE_ERR_INCORRECT_PARAMETER, "Incorrect slot number");
    CHECK_NOT_ZERO_RET(_secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(keypair_type, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(buf, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(key_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    uint8_t keypair_buf[slot_sz];
    keypair_storage_data *keypair_storage = (keypair_storage_data *)keypair_buf;
    uint16_t data_sz;

    STATUS_CHECK_RET(_secmodule->slot_load(slot, keypair_buf, slot_sz, &data_sz),
                     "Unable to load data from slot %d (%s)",
                     slot,
                     _get_slot_name(slot));

    ret_code = VS_CODE_ERR_CRYPTO;

    CHECK(keypair_storage->private_key_sz != 0, "Zero size private key");
    CHECK(keypair_storage->private_key_sz <= buf_sz,
          "Too big private key %d bytes for buffer %d bytes",
          keypair_storage->private_key_sz,
          buf_sz);

    *key_sz = keypair_storage->private_key_sz;
    *keypair_type = keypair_storage->keypair_type;

    memcpy(buf, keypair_storage->data, *key_sz);

#if SOFT_SECMODULE_EXTRA_DEBUG
    VS_LOG_DEBUG("Private key %d bytes from slot %s with keypair type %s has been loaded",
                 *key_sz,
                 _get_slot_name(slot),
                 vs_secmodule_keypair_type_descr(*keypair_type));
#endif

    ret_code = VS_CODE_OK;

terminate:

    return ret_code;
}

/********************************************************************************/
vs_status_e
_fill_keypair_impl(vs_secmodule_impl_t *secmodule_impl) {
    CHECK_NOT_ZERO_RET(secmodule_impl, VS_CODE_ERR_NULLPTR_ARGUMENT);

    secmodule_impl->create_keypair = vs_secmodule_keypair_create;
    secmodule_impl->set_keypair = vs_secmodule_keypair_set;
    secmodule_impl->get_pubkey = vs_secmodule_keypair_get_pubkey;

    return VS_CODE_OK;
}

/********************************************************************************/
