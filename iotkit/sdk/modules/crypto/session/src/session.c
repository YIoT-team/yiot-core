//  ────────────────────────────────────────────────────────────
//                     ╔╗  ╔╗ ╔══╗      ╔════╗
//                     ║╚╗╔╝║ ╚╣╠╝      ║╔╗╔╗║
//                     ╚╗╚╝╔╝  ║║  ╔══╗ ╚╝║║╚╝
//                      ╚╗╔╝   ║║  ║╔╗║   ║║
//                       ║║   ╔╣╠╗ ║╚╝║   ║║
//                       ╚╝   ╚══╝ ╚══╝   ╚╝
//    ╔╗╔═╗                    ╔╗                     ╔╗
//    ║║║╔╝                   ╔╝╚╗                    ║║
//    ║╚╝╝  ╔══╗ ╔══╗ ╔══╗  ╔╗╚╗╔╝  ╔══╗ ╔╗ ╔╗╔╗ ╔══╗ ║║  ╔══╗
//    ║╔╗║  ║║═╣ ║║═╣ ║╔╗║  ╠╣ ║║   ║ ═╣ ╠╣ ║╚╝║ ║╔╗║ ║║  ║║═╣
//    ║║║╚╗ ║║═╣ ║║═╣ ║╚╝║  ║║ ║╚╗  ╠═ ║ ║║ ║║║║ ║╚╝║ ║╚╗ ║║═╣
//    ╚╝╚═╝ ╚══╝ ╚══╝ ║╔═╝  ╚╝ ╚═╝  ╚══╝ ╚╝ ╚╩╩╝ ║╔═╝ ╚═╝ ╚══╝
//                    ║║                         ║║
//                    ╚╝                         ╚╝
//
//    Lead Maintainer: Roman Kutashenko <kutashenko@gmail.com>
//  ────────────────────────────────────────────────────────────

#include <string.h>
#include <stdbool.h>
#include <stdlib-config.h>
#include <virgil/iot/session/session.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>

static vs_session_key_t _own_key = {0};
static vs_secmodule_impl_t *_secmodule = NULL;

#define SESSION_DEBUG 1
#define SESSION_FULL 1

#if SESSION_FULL

#define KEYS_COUNT_MAX (30)
static vs_session_key_t _ext_keys[KEYS_COUNT_MAX] = {0};
#endif

/******************************************************************************/
vs_status_e
vs_session_init(vs_secmodule_impl_t *secmodule, uint8_t prefix[SESSION_ID_PREFIX_SZ]) {
    CHECK_NOT_ZERO_RET(secmodule, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(secmodule->random, VS_CODE_ERR_ZERO_ARGUMENT);

#if SESSION_FULL
    VS_IOT_MEMSET(_ext_keys, 0, sizeof(vs_session_key_t) * KEYS_COUNT_MAX);
#endif
    _secmodule = secmodule;

    if (!_own_key.ready) {
        VS_IOT_MEMCPY(_own_key.id.prefix, prefix, SESSION_ID_PREFIX_SZ);
#if !SESSION_DEBUG
        STATUS_CHECK_RET(_secmodule->random(_own_key.val, SESSION_KEY_SZ), "Cannot generate session key");
#else
        VS_IOT_MEMSET(_own_key.val, 0xAA, SESSION_KEY_SZ);
#endif
        _own_key.ready = true;
    }

    return VS_CODE_OK;
}

/******************************************************************************/
static bool
_cmp_key_id(const vs_session_id_t *k1, const vs_session_id_t *k2) {
    CHECK_NOT_ZERO_RET(k1, false);
    CHECK_NOT_ZERO_RET(k2, false);
    return 0 == VS_IOT_MEMCMP(k1->prefix, k2->prefix, SESSION_ID_PREFIX_SZ);
}

/******************************************************************************/
#if SESSION_FULL
static vs_status_e
_find_pos(const vs_session_id_t *k1, bool adding, size_t *pos) {
    CHECK_NOT_ZERO_RET(k1, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(pos, VS_CODE_ERR_ZERO_ARGUMENT);

    int i;
    int empty_pos = -1;
    for (i = 0; i < KEYS_COUNT_MAX; i++) {
        if (!_ext_keys[i].ready) {
            if (empty_pos < 0) {
                empty_pos = i;
            }
        } else if (_cmp_key_id(k1, &_ext_keys[i].id)) {
            *pos = i;
            return VS_CODE_OK;
        }
    }

    if (adding && empty_pos >= 0) {
        *pos = empty_pos;
        return VS_CODE_OK;
    }

    return VS_CODE_ERR_NOT_FOUND;
}
#endif

/******************************************************************************/
vs_status_e
vs_session_get_own_key(vs_session_key_t *key) {
    CHECK_NOT_ZERO_RET(key, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(_own_key.ready, VS_CODE_ERR_NOINIT);
    VS_IOT_MEMCPY(key, &_own_key, sizeof(_own_key));
    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_session_add_key(const vs_session_key_t *key) {
    vs_status_e ret_code;
#if SESSION_FULL
    size_t pos;
    CHECK_NOT_ZERO_RET(key, VS_CODE_ERR_ZERO_ARGUMENT);
    STATUS_CHECK_RET(_find_pos(&key->id, true, &pos), "Too many keys");
    VS_IOT_MEMCPY(&_ext_keys[pos], key, sizeof(*key));
    return VS_CODE_OK;
#else
    return VS_CODE_ERR_NOT_IMPLEMENTED;
#endif
}

/******************************************************************************/
vs_status_e
vs_session_remove_key(const vs_session_id_t *id) {
    vs_status_e ret_code;
#if SESSION_FULL
    size_t pos;
    CHECK_NOT_ZERO_RET(id, VS_CODE_ERR_ZERO_ARGUMENT);
    STATUS_CHECK_RET(_find_pos(id, true, &pos), "Too many keys");
    VS_IOT_MEMSET(&_ext_keys[pos], 0, sizeof(vs_session_key_t));
    return VS_CODE_OK;
#else
    return VS_CODE_ERR_NOT_IMPLEMENTED;
#endif
}

/******************************************************************************/
vs_status_e
vs_session_get_key(const vs_session_id_t *id, vs_session_key_t *key) {
    vs_status_e ret_code;

    CHECK_NOT_ZERO_RET(id, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(key, VS_CODE_ERR_ZERO_ARGUMENT);

    if (_own_key.ready && _cmp_key_id(id, &_own_key.id)) {
        VS_IOT_MEMCPY(key, &_own_key, sizeof(_own_key));
        return VS_CODE_OK;
    }

#if SESSION_FULL
    size_t pos;
    STATUS_CHECK_RET(_find_pos(id, false, &pos), "");
    VS_IOT_MEMCPY(key, &_ext_keys[pos], sizeof(*key));
#else
    return VS_CODE_ERR_NOT_FOUND;
#endif
    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_session_encrypt(const vs_session_id_t *id, uint8_t *data, size_t data_sz, size_t *res_data_sz) {
    vs_status_e ret_code;
    uint8_t add_data = 0;
    uint8_t iv_data[VS_AES_256_GCM_IV_SIZE];
    vs_session_key_t key;

    CHECK_NOT_ZERO_RET(id, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(res_data_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // Fill IV
    VS_IOT_MEMSET(iv_data, 0, VS_AES_256_GCM_IV_SIZE);
    VS_IOT_MEMCPY(iv_data, id->prefix, SESSION_ID_PREFIX_SZ);

    // Get session key
    STATUS_CHECK_RET(vs_session_get_key(id, &key), "Cannot find session key");

    // Fill padding
    uint8_t padding_val = VS_AES_256_BLOCK_SIZE - (data_sz % VS_AES_256_BLOCK_SIZE);
    VS_IOT_MEMSET(&data[data_sz], padding_val, padding_val);

    size_t padded_data_sz = data_sz + padding_val;
    size_t enc_data_sz = padded_data_sz + VS_AES_256_GCM_AUTH_TAG_SIZE;
    uint8_t encrypted_data[enc_data_sz];

    // AES 256 GCM encryption
    STATUS_CHECK_RET(_secmodule->aes_encrypt(VS_AES_GCM,
                                             key.val,
                                             VS_AES_256_KEY_BITLEN,
                                             iv_data,
                                             VS_AES_256_GCM_IV_SIZE,
                                             &add_data,
                                             0,
                                             padded_data_sz,
                                             data,
                                             encrypted_data,
                                             &encrypted_data[padded_data_sz],
                                             VS_AES_256_GCM_AUTH_TAG_SIZE),
                     "Unable to encrypt by using AES");

    VS_LOG_HEX(VS_LOGLEV_DEBUG, "PADDED DATA: ", data, padded_data_sz);

    *res_data_sz = sizeof(encrypted_data);
    VS_IOT_MEMCPY(data, encrypted_data, *res_data_sz);

    VS_LOG_HEX(VS_LOGLEV_DEBUG, "ENC DATA: ", data, *res_data_sz);

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_session_decrypt(const vs_session_id_t *id, uint8_t *data, size_t data_sz, size_t *res_data_sz) {
    vs_status_e ret_code;
    uint8_t decrypted_data[data_sz];
    uint8_t iv_data[VS_AES_256_GCM_IV_SIZE];
    vs_session_key_t key;

    VS_LOG_HEX(VS_LOGLEV_DEBUG, "ENC DATA: ", data, data_sz);

    CHECK_NOT_ZERO_RET(id, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(res_data_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // Fill IV
    VS_IOT_MEMSET(iv_data, 0, VS_AES_256_GCM_IV_SIZE);
    VS_IOT_MEMCPY(iv_data, id->prefix, SESSION_ID_PREFIX_SZ);

    // Get session key
    STATUS_CHECK_RET(vs_session_get_key(id, &key), "Cannot find session key");

    STATUS_CHECK_RET(_secmodule->aes_auth_decrypt(VS_AES_GCM,
                                                  key.val,
                                                  VS_AES_256_KEY_BITLEN,
                                                  iv_data,
                                                  VS_AES_256_GCM_IV_SIZE,
                                                  NULL,
                                                  0,
                                                  data_sz - VS_AES_256_GCM_AUTH_TAG_SIZE,
                                                  data,
                                                  decrypted_data,
                                                  &data[data_sz - VS_AES_256_GCM_AUTH_TAG_SIZE],
                                                  VS_AES_256_GCM_AUTH_TAG_SIZE),
                     "Unable to decrypt");

    *res_data_sz = sizeof(decrypted_data) - VS_AES_256_GCM_AUTH_TAG_SIZE;
    uint8_t padding_val = decrypted_data[*res_data_sz - 1];

    VS_LOG_HEX(VS_LOGLEV_DEBUG, "PADDED DATA: ", decrypted_data, *res_data_sz);

    CHECK_RET(padding_val <= VS_AES_256_BLOCK_SIZE, VS_CODE_ERR_INCORRECT_ARGUMENT, "Wrong padding");

    *res_data_sz -= padding_val;
    VS_IOT_MEMCPY(data, decrypted_data, *res_data_sz);

    return VS_CODE_OK;
}

/******************************************************************************/
