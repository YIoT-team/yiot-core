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

#ifndef KS_IOT_USERS_H
#define KS_IOT_USERS_H

#include <stdint.h>
#include <virgil/iot/storage_hal/storage_hal.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/users/users-structs.h>
#include <virgil/iot/provision/provision-structs.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

vs_status_e
vs_users_init(void);

vs_status_e
vs_users_deinit(void);

vs_status_e
vs_users_reset(vs_user_type_t type);

vs_status_e
vs_users_add(vs_user_type_t type, const char *name, const vs_pubkey_dated_t *pubkey);

vs_status_e
vs_users_remove_by_name(vs_user_type_t type, const char *name);

vs_status_e
vs_users_remove_by_key(vs_user_type_t type, const vs_pubkey_dated_t *pubkey);

vs_status_e
vs_users_remove_by_num(vs_user_type_t type, uint16_t pos);

vs_status_e
vs_users_get_amount(vs_user_type_t type, uint16_t *amount);

vs_status_e
vs_users_get_by_num(vs_user_type_t type,
                    uint16_t pos,
                    char *name,
                    uint16_t name_buf_sz,
                    vs_pubkey_dated_t *pubkey,
                    uint16_t key_buf_sz,
                    uint16_t *key_sz);

vs_status_e
vs_users_get_key(vs_user_type_t type, const char *name, vs_pubkey_dated_t *pubkey, uint16_t buf_sz, uint16_t *key_sz);

vs_status_e
vs_users_get_name(vs_user_type_t type, const vs_pubkey_dated_t *pubkey, char *name, uint16_t buf_sz);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // KS_IOT_USERS_H
