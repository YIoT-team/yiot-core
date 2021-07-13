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
#include <virgil/iot/high-level/high-level-crypto.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>

/******************************************************************************/
vs_status_e
vs_crypto_hl_verify(vs_secmodule_impl_t *_secmodule,
                    const uint8_t *data,
                    size_t data_sz,
                    const vs_sign_t *sign,
                    const vs_pubkey_dated_t *required_signer) {
    // Check input parameters
    CHECK_NOT_ZERO_RET(_secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_secmodule->ecdsa_verify, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(sign, VS_CODE_ERR_NULLPTR_ARGUMENT);

    vs_status_e ret_code;
    int hash_size;

    // Calculate hash of stuff under signature
    hash_size = vs_secmodule_get_hash_len(sign->hash_type);
    CHECK_RET(hash_size > 0, VS_CODE_ERR_CRYPTO, "Unsupported hash type");
    uint8_t hash[hash_size];
    uint16_t res_sz;
    STATUS_CHECK_RET(_secmodule->hash(sign->hash_type, data, data_sz, hash, hash_size, &res_sz), "Error hash create");

    // Verify signature
    uint16_t sign_sz = vs_secmodule_get_signature_len(sign->ec_type);
    const uint8_t *signer_key = &sign->raw_sign_pubkey[sign_sz];
    size_t signer_key_sz = vs_secmodule_get_pubkey_len(sign->ec_type);
    STATUS_CHECK_RET(
            _secmodule->ecdsa_verify(
                    sign->ec_type, signer_key, signer_key_sz, sign->hash_type, hash, sign->raw_sign_pubkey, sign_sz),
            "Signature is wrong");

    if (required_signer) {
        const uint8_t *required_signer_key =
                &required_signer->pubkey.meta_and_pubkey[required_signer->pubkey.meta_data_sz];

        CHECK_RET(0 == VS_IOT_MEMCMP(required_signer_key, signer_key, signer_key_sz), VS_CODE_ERR_USER, "Wrong signer");
    }

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_crypto_hl_sign(vs_secmodule_impl_t *_secmodule,
                  const uint8_t *data,
                  size_t data_sz,
                  vs_sign_t *sign,
                  uint16_t sign_buf_sz,
                  uint16_t *sign_sz_res) {

    // Check input parameters
    CHECK_NOT_ZERO_RET(_secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_secmodule->get_pubkey, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_secmodule->ecdsa_sign, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(sign, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(sign_sz_res, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(sign_buf_sz > sizeof(vs_sign_t), VS_CODE_ERR_NULLPTR_ARGUMENT);

    vs_status_e ret_code;

    // Prepare signature info
    sign->hash_type = VS_HASH_SHA_256;
    sign->ec_type = VS_KEYPAIR_EC_SECP256R1;
    sign->signer_type = VS_KEY_IOT_DEVICE;

    // Create hash
    int hash_size = vs_secmodule_get_hash_len(sign->hash_type);
    CHECK_RET(hash_size > 0, VS_CODE_ERR_CRYPTO, "Unsupported hash type");
    uint8_t hash[hash_size];
    uint16_t res_sz;
    STATUS_CHECK_RET(_secmodule->hash(sign->hash_type, data, data_sz, hash, hash_size, &res_sz), "Error hash create");

    // Sign data
    uint16_t buf_sz = sign_buf_sz - sizeof(vs_sign_t);
    uint16_t sign_sz;
    STATUS_CHECK_RET(
            _secmodule->ecdsa_sign(PRIVATE_KEY_SLOT, sign->hash_type, hash, sign->raw_sign_pubkey, buf_sz, &sign_sz),
            "Unable to sign");
    buf_sz -= sign_sz;

    // Fill own public key
    vs_secmodule_keypair_type_e pubkey_type;
    uint16_t pubkey_sz;
    STATUS_CHECK_RET(
            _secmodule->get_pubkey(PRIVATE_KEY_SLOT, &sign->raw_sign_pubkey[sign_sz], buf_sz, &pubkey_sz, &pubkey_type),
            "Unable to get public key");

    *sign_sz_res = sizeof(vs_sign_t) + vs_secmodule_get_signature_len(sign->ec_type) +
                   vs_secmodule_get_pubkey_len(sign->ec_type);

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_crypto_hl_dated_key_size(const vs_pubkey_dated_t *pubkey, uint16_t *key_sz) {
    CHECK_NOT_ZERO_RET(pubkey, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(key_sz, VS_CODE_ERR_ZERO_ARGUMENT);

    *key_sz = sizeof(vs_pubkey_dated_t) + vs_secmodule_get_pubkey_len(pubkey->pubkey.ec_type) +
              pubkey->pubkey.meta_data_sz;

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_crypto_hl_cert_size(const vs_cert_t *cert, uint16_t *cert_sz) {
    CHECK_NOT_ZERO_RET(cert, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(cert_sz, VS_CODE_ERR_ZERO_ARGUMENT);

    *cert_sz = sizeof(vs_cert_t) + cert->key_sz + cert->signature_sz;

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_crypto_hl_verify_cert(vs_secmodule_impl_t *_secmodule, const vs_cert_t *cert) {
    vs_status_e ret_code;

    // Check input parameters
    CHECK_NOT_ZERO_RET(_secmodule, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(cert, VS_CODE_ERR_ZERO_ARGUMENT);

    // Get certificate parts
    const vs_pubkey_dated_t *key = (vs_pubkey_dated_t *)cert->raw_cert;
    const vs_sign_t *sign = (vs_sign_t *)&cert->raw_cert[cert->key_sz];
    uint16_t key_sz;

    // Check public key size
    STATUS_CHECK_RET(vs_crypto_hl_dated_key_size(key, &key_sz), "Cannot get key size");
    CHECK_RET(key_sz == cert->key_sz, VS_CODE_ERR_INCORRECT_ARGUMENT, "Incorrect certificate");

    // Check if signature correct
    STATUS_CHECK_RET(vs_crypto_hl_verify(_secmodule, (const uint8_t *)key, key_sz, sign, NULL),
                     "Cannot verify certificate");

    // TODO: Should we check for signer here ?


    return VS_CODE_OK;
}


/******************************************************************************/
