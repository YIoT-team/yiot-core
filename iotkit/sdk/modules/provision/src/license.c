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

#include <stdbool.h>

#include <stdlib-config.h>
#include <endian-config.h>

#include <virgil/iot/base64/base64.h>
#include <virgil/iot/provision/license.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/protocols/snap/prvs/prvs-structs.h>
#include <virgil/iot/provision/provision.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/high-level/high-level-crypto.h>
#include <virgil/iot/json/json_parser.h>

#define VS_LICENSE_JSON_DATA_FIELD "license"
#define VS_LICENSE_JSON_SIGNATURE_FIELD "signature"

static vs_secmodule_impl_t *_secmodule = NULL;

/******************************************************************************/
vs_status_e
vs_license_init(vs_secmodule_impl_t *secmodule) {
    CHECK_NOT_ZERO_RET(secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(secmodule->slot_load, VS_CODE_ERR_NULLPTR_ARGUMENT);
    _secmodule = secmodule;

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_license_get(uint8_t *license_buf, uint16_t buf_sz, uint16_t *license_sz) {
    vs_status_e ret_code;

    *license_sz = 0;

    // Check input parameters
    CHECK_NOT_ZERO_RET(license_buf, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(buf_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(license_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // Check if provision ready
    CHECK_RET(vs_provision_is_ready(), VS_CODE_ERR_NOT_FOUND, "Provision is not ready");

    // Load license
    STATUS_CHECK_RET(_secmodule->slot_load(LICENSE_SLOT,
                                           license_buf,
                                           buf_sz,
                                           license_sz),
                     "Unable to load license");

    // Verify a license
    ret_code = vs_license_verify(license_buf, *license_sz);

    return ret_code;
}

/******************************************************************************/
vs_status_e
vs_license_parse(uint8_t *license_buf, uint16_t license_sz,
                 char *data_buf, uint16_t data_buf_sz, uint16_t *data_sz,
                 char *sign_buf, uint16_t sign_buf_sz, uint16_t *sign_sz) {
    vs_status_e res = VS_CODE_ERR_JSON;

    jobj_t jobj;

    // Check input parameters
    CHECK_NOT_ZERO_RET(license_buf, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(license_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_buf, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_buf_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(sign_buf, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(sign_buf_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(sign_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // Parse JSON with a signed license
    if (json_parse_start(&jobj, (char *)license_buf, license_sz) != VS_JSON_ERR_OK) {
        return VS_CODE_ERR_JSON;
    }

    // Get License data
    CHECK(VS_JSON_ERR_OK ==
                  json_get_val_str(&jobj, VS_LICENSE_JSON_DATA_FIELD, data_buf, (int)(data_buf_sz)),
          "Cannot get License data");
    *data_sz = VS_IOT_STRLEN(data_buf);

    // Get Signature data
    CHECK(VS_JSON_ERR_OK ==
                  json_get_val_str(&jobj, VS_LICENSE_JSON_SIGNATURE_FIELD, sign_buf, (int)(sign_buf_sz)),
          "Cannot get License signature");
    *sign_sz = VS_IOT_STRLEN(sign_buf);

    res = VS_CODE_OK;

terminate:
    json_parse_stop(&jobj);

    return res;
}

/******************************************************************************/
vs_status_e
vs_license_plain_data(uint8_t *license_buf, uint16_t license_sz,
                      char *data_buf, uint16_t data_buf_sz, uint16_t *data_sz) {

    vs_status_e res = VS_CODE_ERR_UNSUPPORTED;
    char b64_data[VS_LICENSE_DATA_MAX_SZ];
    char b64_sign[VS_LICENSE_SIGN_MAX_SZ];
    uint16_t b64_data_sz = 0;
    uint16_t b64_sign_sz = 0;
    int res_sz;
    int data_b64_decoded_len;

    // Check input parameters
    CHECK_NOT_ZERO_RET(license_buf, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(license_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_buf, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_buf_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // Prepare result
    *data_sz = 0;

    // Parse signed license
    STATUS_CHECK(vs_license_parse(license_buf, license_sz,
                                 b64_data, VS_LICENSE_DATA_MAX_SZ, &b64_data_sz,
                                  b64_sign, VS_LICENSE_SIGN_MAX_SZ, &b64_sign_sz),
                 "Cannot parse signed license");

    // Base64 decode of data
    data_b64_decoded_len = base64decode_len(b64_data, (int)VS_IOT_STRLEN(b64_data));
    CHECK(data_b64_decoded_len < data_buf_sz, "Data buffer too small");
    res_sz = data_buf_sz;
    CHECK(base64decode(b64_data,
                       (int)VS_IOT_STRLEN(b64_data),
                       (uint8_t *)data_buf,
                       &res_sz),
          "Cant't decode base64 license data");
    *data_sz = res_sz;

    res = VS_CODE_OK;

terminate:

    return res;
}

/******************************************************************************/
vs_status_e
vs_license_verify(uint8_t *license_buf, uint16_t license_sz) {
    vs_status_e res = VS_CODE_ERR_UNSUPPORTED;
    char b64_data[VS_LICENSE_DATA_MAX_SZ];
    char b64_sign[VS_LICENSE_SIGN_MAX_SZ];
    char signVirgil[VS_LICENSE_SIGN_MAX_SZ];
    uint16_t b64_data_sz = 0;
    uint16_t b64_sign_sz = 0;
    int res_sz;
    int sign_b64_decoded_len;

    // Check input parameters
    CHECK_NOT_ZERO_RET(license_buf, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(license_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // Parse signed license
    STATUS_CHECK(vs_license_parse(license_buf, license_sz,
                                  b64_data, VS_LICENSE_DATA_MAX_SZ, &b64_data_sz,
                                  b64_sign, VS_LICENSE_SIGN_MAX_SZ, &b64_sign_sz),
                 "Cannot parse signed license");

    // Base64 decode of signature
    sign_b64_decoded_len = base64decode_len(b64_sign, (int)VS_IOT_STRLEN(b64_sign));
    CHECK(sign_b64_decoded_len < VS_LICENSE_SIGN_MAX_SZ, "Data buffer too small");
    res_sz = VS_LICENSE_SIGN_MAX_SZ;
    CHECK(base64decode(b64_sign,
                       (int)VS_IOT_STRLEN(b64_sign),
                       (uint8_t *)signVirgil,
                       &res_sz),
          "Cant't decode base64 license signature");

    // Verify signature
    /*----Verify cloud signature----*/
    bool key_present = true;
    bool verified = false;
    vs_provision_tl_find_ctx_t search_ctx;
    uint8_t *pubkey = NULL;
    uint16_t pubkey_sz = 0;
    uint8_t *meta = NULL;
    vs_pubkey_dated_t *pubkey_dated = NULL;
    uint16_t meta_sz = 0;

    uint8_t hash[VS_HASH_SHA256_LEN];
    uint16_t hash_sz;

    // Prepare converted signature
    uint8_t sign[VS_SIGNATURE_MAX_LEN];
    CHECK(VS_CODE_OK == vs_secmodule_virgil_secp256_signature_to_tiny(
                                (uint8_t *)signVirgil, sign_b64_decoded_len, sign, sizeof(sign)),
          "Wrong signature format");

    // Find the first factory key
    CHECK(VS_CODE_OK == vs_provision_tl_find_first_key(
                                &search_ctx, VS_KEY_FACTORY, &pubkey_dated, &pubkey, &pubkey_sz, &meta, &meta_sz),
          "Can't find the first factory key in TL");

    do {
        // Calculate required size of a signature
        int sign_sz = vs_secmodule_get_signature_len(pubkey_dated->pubkey.ec_type);
        CHECK(sign_sz > 0, "Incorrect ec type of factory key");

        // Hash data
        CHECK(VS_CODE_OK == _secmodule->hash(VS_HASH_SHA_256,
                                             (uint8_t *)b64_data,
                                             b64_data_sz,
                                             hash,
                                             sizeof(hash),
                                             &hash_sz),
              "Error during hash calculate");

        // Verify signature
        verified = VS_CODE_OK == _secmodule->ecdsa_verify(pubkey_dated->pubkey.ec_type,
                                                     pubkey,
                                                     pubkey_sz,
                                                     VS_HASH_SHA_256,
                                                     hash,
                                                     sign,
                                                     sizeof(sign));

        // Stop keys search if verification is done
        if (verified) {
            break;
        }

        // Try to find a next key
        key_present = VS_CODE_OK == vs_provision_tl_find_next_key(&search_ctx,
                                      &pubkey_dated,
                                      &pubkey,
                                      &pubkey_sz,
                                      &meta,
                                      &meta_sz);

    } while(key_present);

    res = verified ? VS_CODE_OK : VS_CODE_ERR_VERIFY;

terminate:

    return res;
}

/******************************************************************************/
vs_status_e
vs_license_save(uint8_t *license_buf, uint16_t license_sz) {
    vs_status_e res = VS_CODE_ERR_UNSUPPORTED;
    uint16_t slot;

    // Check input parameters
    CHECK_NOT_ZERO_RET(license_buf, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(license_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // Verify a license
    STATUS_CHECK(vs_license_verify(license_buf, license_sz), "Cannot verify a license to be saved");

    // Save License
    STATUS_CHECK(vs_provision_get_slot_num((vs_provision_element_id_e)VS_PRVS_LIC, &slot), "Cannot get license slot");
    STATUS_CHECK(_secmodule->slot_save(slot, license_buf, license_sz), "Cannot save license");

    res = VS_CODE_OK;

terminate:

    return res;
}

/******************************************************************************/
