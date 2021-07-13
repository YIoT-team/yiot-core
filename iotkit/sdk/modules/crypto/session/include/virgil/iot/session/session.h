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

#ifndef VS_CRYPTO_SESSION_H
#define VS_CRYPTO_SESSION_H

#include <stdint.h>
#include <stddef.h>

#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/session/session-structs.h>
#include <virgil/iot/secmodule/secmodule.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

vs_status_e
vs_session_init(vs_secmodule_impl_t *secmodule, uint8_t prefix[SESSION_ID_PREFIX_SZ]);

vs_status_e
vs_session_get_own_key(vs_session_key_t *key);

vs_status_e
vs_session_add_key(const vs_session_key_t *key);

vs_status_e
vs_session_remove_key(const vs_session_id_t *id);

vs_status_e
vs_session_get_key(const vs_session_id_t *id, vs_session_key_t *key);

vs_status_e
vs_session_encrypt(const vs_session_id_t *id, uint8_t *data, size_t data_sz, size_t *res_data_sz);

vs_status_e
vs_session_decrypt(const vs_session_id_t *id, uint8_t *data, size_t data_sz, size_t *res_data_sz);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_CRYPTO_SESSION_H
