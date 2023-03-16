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

#define VS_LICENSE_JSON_TIMESTAMP_FIELD "timestamp"
#define VS_LICENSE_JSON_EXTRA_DATA_FIELD "data"
#define VS_LICENSE_JSON_DEVICE_DATA_FIELD "device"

#define VS_LICENSE_JSON_MANUFACTURER_FIELD "manufacturer"
#define VS_LICENSE_JSON_MODEL_FIELD "model"
#define VS_LICENSE_JSON_roles_FIELD "roles"
#define VS_LICENSE_JSON_MAC_FIELD "mac"
#define VS_LICENSE_JSON_SERIAL_FIELD "serial"
#define VS_LICENSE_JSON_PUBKEY_FIELD "publicKeyTiny"
#define VS_LICENSE_JSON_DEVICE_SIGN_FIELD "signature"
#define VS_LICENSE_JSON_KEY_TYPE_FIELD "key_type"
#define VS_LICENSE_JSON_EC_TYPE_FIELD "ec_type"

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
static void
_str_to_bytes(uint8_t *dst, const char *src, size_t elem_buf_size) {
    size_t pos;
    size_t len;

    assert(src && *src);
    assert(elem_buf_size);

    VS_IOT_MEMSET(dst, 0, elem_buf_size);

    len = VS_IOT_STRLEN(src);
    for (pos = 0; pos < len && pos < elem_buf_size; ++pos, ++src, ++dst) {
        *dst = *src;
    }
}
/******************************************************************************/
vs_status_e
vs_license_plain_data_parse(uint8_t *license_data, uint16_t license_data_sz,
                            uint64_t *timestamp,
                            vs_device_manufacture_id_t manufacturer,
                            vs_device_type_t model,
                            vs_device_serial_t serial,
                            uint32_t *roles,
                            vs_mac_addr_t *mac,
                            uint8_t *key_type,
                            uint8_t *ec_type,
                            char *pubkey_buf, uint16_t pubkey_buf_sz, uint16_t *pubkey_sz,
                            char *sign_buf, uint16_t sign_buf_sz, uint16_t *sign_sz,
                            char *extra_data_buf, uint16_t extra_data_buf_sz, uint16_t *extra_data_sz) {

    vs_status_e res = VS_CODE_ERR_JSON;
    jobj_t jobj;
    char tmp_data[VS_LICENSE_DATA_MAX_SZ];
    char serial_data[sizeof(vs_device_serial_t) * 2];
    int64_t ts;
    int tmp_int;

    // Check input parameters
    CHECK_NOT_ZERO_RET(license_data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(license_data_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(timestamp, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(manufacturer, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(model, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(serial, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(roles, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(mac, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(key_type, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(ec_type, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(pubkey_buf, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(pubkey_buf_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(pubkey_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(sign_buf, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(sign_buf_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(sign_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(extra_data_buf, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(extra_data_buf_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(extra_data_sz, VS_CODE_ERR_NULLPTR_ARGUMENT);

    // Prepare result
    VS_IOT_MEMSET(manufacturer, 0, sizeof(*manufacturer));
    VS_IOT_MEMSET(model, 0, sizeof(*model));
    VS_IOT_MEMSET(serial, 0, sizeof(*serial));
    VS_IOT_MEMSET(mac, 0, sizeof(*mac));
    VS_IOT_MEMSET(pubkey_buf, 0, pubkey_buf_sz);
    VS_IOT_MEMSET(sign_buf, 0, sign_buf_sz);
    VS_IOT_MEMSET(extra_data_buf, 0, extra_data_buf_sz);
    *pubkey_sz = 0;
    *sign_sz = 0;
    *extra_data_sz = 0;
    *timestamp = 0;
    *roles = 0;

    // Parse JSON with a signed license
    if (json_parse_start(&jobj, (char *)license_data, license_data_sz) != VS_JSON_ERR_OK) {
        return VS_CODE_ERR_JSON;
    }

    // Get timestamp
    CHECK(VS_JSON_ERR_OK ==
                  json_get_val_int64(&jobj, VS_LICENSE_JSON_TIMESTAMP_FIELD, &ts),
                  "Cannot get timestamp");
    *timestamp = ts;

    // Get Extra data
    CHECK(VS_JSON_ERR_OK ==
                  json_get_part_str(&jobj, VS_LICENSE_JSON_EXTRA_DATA_FIELD, extra_data_buf, (int)(extra_data_buf_sz)),
          "Cannot get Extra data");
    *extra_data_sz = VS_IOT_STRLEN(extra_data_buf);

    // Step into 'device' elements
    CHECK(VS_JSON_ERR_OK ==
                  json_get_composite_object(&jobj, VS_LICENSE_JSON_DEVICE_DATA_FIELD),
          "Cannot get Device data");

    // Get Manufacturer
    CHECK(VS_JSON_ERR_OK ==
                  json_get_val_str(&jobj, VS_LICENSE_JSON_MANUFACTURER_FIELD, tmp_data, VS_LICENSE_DATA_MAX_SZ),
          "Cannot get Manufacturer");
    _str_to_bytes(manufacturer, tmp_data, sizeof(vs_device_manufacture_id_t));

    // Get Model
    CHECK(VS_JSON_ERR_OK ==
                  json_get_val_str(&jobj, VS_LICENSE_JSON_MODEL_FIELD, tmp_data, VS_LICENSE_DATA_MAX_SZ),
          "Cannot get Model");
    *(uint32_t*)model = strtoull(tmp_data, NULL, 0);

    // Get MAC address
    CHECK(VS_JSON_ERR_OK ==
                  json_get_val_str(&jobj, VS_LICENSE_JSON_MAC_FIELD, tmp_data, VS_LICENSE_DATA_MAX_SZ),
          "Cannot get MAC address");
    CHECK( 6 == sscanf(tmp_data, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                      &mac->bytes[0], &mac->bytes[1], &mac->bytes[2],
                      &mac->bytes[3], &mac->bytes[4], &mac->bytes[5] ),
          "Cannot convert MAC address");

    // Get Key Type
    CHECK(VS_JSON_ERR_OK ==
                  json_get_val_int(&jobj, VS_LICENSE_JSON_KEY_TYPE_FIELD, &tmp_int),
          "Cannot get key type");
    *key_type = tmp_int;

    // Get EC Type
    CHECK(VS_JSON_ERR_OK ==
                  json_get_val_int(&jobj, VS_LICENSE_JSON_EC_TYPE_FIELD, &tmp_int),
          "Cannot get EC type");
    *ec_type = tmp_int;

    // Get RAW public key
    CHECK(VS_JSON_ERR_OK ==
                  json_get_val_str(&jobj, VS_LICENSE_JSON_PUBKEY_FIELD, tmp_data, VS_LICENSE_DATA_MAX_SZ),
          "Cannot get RAW public key");
    tmp_int = pubkey_buf_sz;
    CHECK(base64decode(tmp_data,
                       (int)VS_IOT_STRLEN(tmp_data),
                       (uint8_t *)pubkey_buf,
                       &tmp_int),
          "Cannot decode base64 RAW public key");
    *pubkey_sz = tmp_int;

    // Get Device signature key
    CHECK(VS_JSON_ERR_OK ==
                  json_get_val_str(&jobj, VS_LICENSE_JSON_DEVICE_SIGN_FIELD, tmp_data, VS_LICENSE_DATA_MAX_SZ),
          "Cannot get device signature");
    tmp_int = sign_buf_sz;
    CHECK(base64decode(tmp_data,
                       (int)VS_IOT_STRLEN(tmp_data),
                       (uint8_t *)sign_buf,
                       &tmp_int),
          "Cannot decode base64 device signature");
    *sign_sz = tmp_int;

    // Get Serial number
    CHECK(VS_JSON_ERR_OK ==
                  json_get_val_str(&jobj, VS_LICENSE_JSON_SERIAL_FIELD, tmp_data, VS_LICENSE_DATA_MAX_SZ),
          "Cannot get Serial number");
    tmp_int = sizeof(serial_data);
    CHECK(base64decode(tmp_data,
                       (int)VS_IOT_STRLEN(tmp_data),
                       (uint8_t *)serial_data,
                       &tmp_int),
          "Cannot decode base64 device serial number");
    CHECK(tmp_int <= sizeof(vs_device_serial_t), "Incorrect serial number");
    VS_IOT_MEMSET(serial, 0, sizeof(vs_device_serial_t));
    VS_IOT_MEMCPY(serial, serial_data, tmp_int);

    res = VS_CODE_OK;

terminate:
    json_parse_stop(&jobj);

    return res;
}

/******************************************************************************/
vs_status_e
vs_license_matches(uint8_t *license, uint16_t license_sz,
                   uint8_t *raw_pubkey, uint16_t raw_pubkey_sz,
                   vs_mac_addr_t mac_addr,
                   vs_device_serial_t serial_number,
                   vs_device_manufacture_id_t manufacturer,
                   vs_device_type_t model) {

    vs_status_e ret_code;
    uint8_t license_data[VS_LICENSE_DATA_MAX_SZ];
    uint16_t license_data_sz = 0;
    uint64_t lic_timestamp = 0;
    vs_device_manufacture_id_t lic_manufacturer = {0};
    vs_device_type_t lic_model = {0};
    vs_device_serial_t lic_serial = {0};
    uint32_t lic_roles = 0;
    vs_mac_addr_t lic_mac;
    uint8_t lic_key_type = 0;
    uint8_t lic_ec_type = 0;
    char lic_pubkey[VS_LICENSE_KEY_MAX_SZ];
    uint16_t lic_pubkey_sz = 0;
    char lic_sign[VS_LICENSE_SIGN_MAX_SZ];
    uint16_t lic_sign_sz = 0;
    char lic_extra_data[VS_LICENSE_DATA_MAX_SZ];
    uint16_t lic_extra_data_sz = 0;

    // Clean data
    VS_IOT_MEMSET(&lic_mac, 0, sizeof(lic_mac));

    // Get plain data of a license
    STATUS_CHECK_RET(vs_license_plain_data(license, license_sz,
                                            (char *)license_data, VS_LICENSE_DATA_MAX_SZ, &license_data_sz),
                     "Cannot get plain data of a license");

    // Parse plain data
    STATUS_CHECK_RET(vs_license_plain_data_parse(license_data, license_data_sz,
                                                 &lic_timestamp,
                                                 lic_manufacturer,
                                                 lic_model,
                                                 lic_serial,
                                                 &lic_roles,
                                                 &lic_mac,
                                                 &lic_key_type,
                                                 &lic_ec_type,
                                                 lic_pubkey, VS_LICENSE_KEY_MAX_SZ, &lic_pubkey_sz,
                                                 lic_sign, VS_LICENSE_SIGN_MAX_SZ, &lic_sign_sz,
                                                 lic_extra_data, VS_LICENSE_DATA_MAX_SZ, &lic_extra_data_sz),
                     "Cannot parse plain data of a license");

    ret_code = VS_CODE_ERR_VERIFY;

    // Compare RAW public keys
    CHECK(0 == VS_IOT_MEMCMP(raw_pubkey, lic_pubkey, raw_pubkey_sz), "Public keys do mot match");

    // Compare MAC addresses
    CHECK(0 == VS_IOT_MEMCMP(&mac_addr, &lic_mac, sizeof(vs_mac_addr_t)), "MAC addresses do mot match");

    // Compare serial numbers
    CHECK(0 == VS_IOT_MEMCMP(serial_number, &lic_serial, sizeof(vs_device_serial_t)), "Serial numbers do mot match");

    // Compare manufacturer
    CHECK(0 == VS_IOT_MEMCMP(manufacturer, &lic_manufacturer, sizeof(vs_device_manufacture_id_t)), "Manufacturers do mot match");

    // Compare model
    CHECK(0 == VS_IOT_MEMCMP(model, &lic_model, sizeof(vs_device_type_t)), "Models do mot match");

    ret_code = VS_CODE_OK;

terminate:

    return ret_code;
}

/******************************************************************************/
