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

#ifndef VS_CRYPTO_HIGH_LEVEL_H
#define VS_CRYPTO_HIGH_LEVEL_H

#include <stdint.h>
#include <stddef.h>

#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/high-level/high-level-crypto-structs.h>
#include <virgil/iot/secmodule/secmodule.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

vs_status_e
vs_crypto_hl_dated_key_size(const vs_pubkey_dated_t *pubkey, uint16_t *key_sz);

vs_status_e
vs_crypto_hl_cert_size(const vs_cert_t *cert, uint16_t *cert_sz);

vs_status_e
vs_crypto_hl_verify_cert(vs_secmodule_impl_t *_secmodule, const vs_cert_t *cert);

vs_status_e
vs_crypto_hl_verify(vs_secmodule_impl_t *_secmodule,
                    const uint8_t *data,
                    size_t data_sz,
                    const vs_sign_t *sign,
                    const vs_pubkey_dated_t *required_signer);

vs_status_e
vs_crypto_hl_sign(vs_secmodule_impl_t *_secmodule,
                  const uint8_t *data,
                  size_t data_sz,
                  vs_sign_t *sign,
                  uint16_t sign_buf_sz,
                  uint16_t *sign_sz);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_CRYPTO_HIGH_LEVEL_H
