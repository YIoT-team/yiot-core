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

    // Parse JSON license

    return VS_CODE_OK;
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
    char b64_sign[VS_LICENSE_DATA_MAX_SZ];
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
                                  b64_sign, VS_LICENSE_DATA_MAX_SZ, &b64_sign_sz),
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
