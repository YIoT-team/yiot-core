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

#ifndef VS_CRYPTO_HIGH_LEVEL_STRUCTS_H
#define VS_CRYPTO_HIGH_LEVEL_STRUCTS_H

#include <stdint.h>
#include <stddef.h>

#include <virgil/iot/status_code/status_code.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

/** Key type */
    typedef enum {
        VS_KEY_RECOVERY = 0,      /**< Recovery key */
        VS_KEY_AUTH,              /**< Authentication key */
        VS_KEY_TRUSTLIST,         /**< Trust List key*/
        VS_KEY_FIRMWARE,          /**< Firmware key */
        VS_KEY_FACTORY,           /**< Factory key */
        VS_KEY_IOT_DEVICE,        /**< Key of IoT device */
        VS_KEY_USER_DEVICE,       /**< Key ofr user device*/
        VS_KEY_FIRMWARE_INTERNAL, /**< Firmware internal key */
        VS_KEY_AUTH_INTERNAL,     /**< Authentication internal key */
        VS_KEY_CLOUD,             /**< Cloud key */
        VS_KEY_UNSUPPORTED        /**< Unsupported key */
    } vs_key_type_e;

/** Signature type */
    typedef struct __attribute__((__packed__)) {
        uint8_t signer_type;       /**< #vs_key_type_e */
        uint8_t ec_type;           /**< #vs_secmodule_keypair_type_e */
        uint8_t hash_type;         /**< #vs_secmodule_hash_type_e */
        uint8_t raw_sign_pubkey[]; /**< An array with raw signature and public key, size of elements depends on \a ec_type
                                */
    } vs_sign_t;

/** Public key type */
    typedef struct __attribute__((__packed__)) {
        uint8_t key_type;          /**< #vs_key_type_e */
        uint8_t ec_type;           /**< #vs_secmodule_keypair_type_e */
        uint16_t meta_data_sz;     /**< Meta data size */
        uint8_t meta_and_pubkey[]; /**< Meta data and public key, size of element depends on \a ec_type */
    } vs_pubkey_t;

    /** Public key with date information */
    typedef struct __attribute__((__packed__)) {
        uint32_t start_date;  /**< Start date */
        uint32_t expire_date; /**< Expiration date */
        vs_pubkey_t pubkey;   /**< Public key */
    } vs_pubkey_dated_t;

    typedef struct __attribute__((__packed__)) {
        uint16_t signature_sz;          /**< Size of vs_sign_t  */
        uint16_t key_sz;                /**< Size of vs_pubkey_dated_t */
        uint8_t raw_cert[];             /**< Array that contains vs_pubkey_dated_t and vs_sign_t. Because of variable sizes.
                                     */
    } vs_cert_t;

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_CRYPTO_HIGH_LEVEL_STRUCTS_H
