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

#include <stdint.h>
#include <stddef.h>

#include <virgil/iot/users/users.h>
#include <virgil/iot/secbox/secbox.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/provision/provision.h>
#include <virgil/iot/high-level/high-level-crypto.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>
#include <stdlib-config.h>
#include <global-hal.h>

static const char *_file_name_template = "usr_%02u_%03u";
static const char *_file_counter_template = "usr_cnt_%02u";

static uint8_t _users_cells[VS_USER_TYPE_MAX][USER_COUNT_MAX];
static bool _users_cached[VS_USER_TYPE_MAX] = {0};

/******************************************************************************/
static vs_status_e
_create_file_info_name(vs_user_type_t type, vs_storage_element_id_t *id) {
    vs_status_e ret_code;

    CHECK_NOT_ZERO_RET(id, VS_CODE_ERR_ZERO_ARGUMENT);

    VS_IOT_MEMSET(id, 0, sizeof(vs_storage_element_id_t));
    snprintf((char *)id, sizeof(vs_storage_element_id_t) - 1, _file_counter_template, (unsigned int)type);
    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_create_file_name(vs_user_type_t type, uint16_t pos, vs_storage_element_id_t *id) {
    vs_status_e ret_code;

    CHECK_NOT_ZERO_RET(id, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(pos < USER_COUNT_MAX, VS_CODE_ERR_USERS_LIMIT);

    VS_IOT_MEMSET(id, 0, sizeof(vs_storage_element_id_t));
    snprintf((char *)id,
             sizeof(vs_storage_element_id_t) - 1,
             _file_name_template,
             (unsigned int)type,
             (unsigned int)pos);
    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_save_cells_info(vs_user_type_t type) {
    vs_status_e ret_code;
    vs_storage_element_id_t id;

    CHECK_NOT_ZERO_RET(type < VS_USER_TYPE_MAX, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(_users_cached[type], VS_CODE_ERR_ZERO_ARGUMENT);
    STATUS_CHECK_RET(_create_file_info_name(type, &id), "Cannot create file name with users amount");
    STATUS_CHECK_RET(vs_secbox_save(VS_SECBOX_SIGNED_AND_ENCRYPTED, id, _users_cells[type], USER_COUNT_MAX),
                     "Cannot save users cells info");
    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_cache_cells_info(vs_user_type_t type) {
    vs_status_e ret_code;
    vs_storage_element_id_t id;
    size_t data_sz;

    if (_users_cached[type]) {
        return VS_CODE_OK;
    }

    CHECK_NOT_ZERO_RET(type < VS_USER_TYPE_MAX, VS_CODE_ERR_ZERO_ARGUMENT);
    STATUS_CHECK_RET(_create_file_info_name(type, &id), "Cannot create file name with users amount");
    if (VS_CODE_OK != vs_secbox_load(id, _users_cells[type], USER_COUNT_MAX, &data_sz)) {
        VS_LOG_WARNING("Cannot get users info. Creating an empty info");
        VS_IOT_MEMSET(_users_cells[type], 0, USER_COUNT_MAX);
    }

    _users_cached[type] = true;

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_get_by_raw_pos(vs_user_type_t type,
                uint16_t pos,
                char *name,
                uint16_t name_buf_sz,
                vs_pubkey_dated_t *pubkey,
                uint16_t key_buf_sz,
                uint16_t *key_sz) {
    vs_status_e ret_code;
    vs_storage_element_id_t id;
    size_t data_sz;
    uint8_t data_buf[USER_BUF_SZ_MAX];
    vs_pubkey_dated_t *loaded_pubkey;

    // Check parameters
    CHECK_NOT_ZERO_RET(type < VS_USER_TYPE_MAX, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(pos < USER_COUNT_MAX, VS_CODE_ERR_USERS_LIMIT);
    CHECK_NOT_ZERO_RET(name_buf_sz >= USER_NAME_SZ_MAX, VS_CODE_ERR_TOO_SMALL_BUFFER);

    // Check if user cell active
    STATUS_CHECK_RET(_cache_cells_info(type), "Cannot cache users info");
    CHECK_RET(_users_cells[type][pos], VS_CODE_ERR_USER_NOT_FOUND, "User not found");

    // Load user info
    STATUS_CHECK_RET(_create_file_name(type, pos, &id), "Cannot create file name for user file");
    STATUS_CHECK_RET(vs_secbox_load(id, data_buf, USER_BUF_SZ_MAX, &data_sz), "Cannot load user data");
    loaded_pubkey = (vs_pubkey_dated_t *)&data_buf[USER_NAME_SZ_MAX];
    STATUS_CHECK_RET(vs_crypto_hl_dated_key_size(loaded_pubkey, key_sz), "Cannot get key size");
    CHECK_RET(key_buf_sz >= *key_sz, VS_CODE_ERR_TOO_SMALL_BUFFER, "Key buffer too small");

    VS_IOT_MEMCPY(name, data_buf, USER_NAME_SZ_MAX);
    VS_IOT_MEMCPY(pubkey, loaded_pubkey, *key_sz);

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_find_by_name(vs_user_type_t type, const char *name, uint16_t *pos) {
    vs_status_e ret_code;
    int i;
    uint8_t read_name[USER_NAME_SZ_MAX];
    uint8_t read_key[USER_KEY_BUF_SZ_MAX];
    uint16_t key_sz;
    vs_pubkey_dated_t *read_pubkey = (vs_pubkey_dated_t *)read_key;

    // Check input parameters
    CHECK_NOT_ZERO_RET(type < VS_USER_TYPE_MAX, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(name, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(strnlen(name, USER_NAME_SZ_MAX) < USER_NAME_SZ_MAX, VS_CODE_ERR_TOO_SMALL_BUFFER);

    // Prepare info about used cells
    STATUS_CHECK_RET(_cache_cells_info(type), "Cannot cache users info");

    for (i = 0; i < USER_COUNT_MAX; i++) {
        if (_users_cells[type][i]) {
            if (VS_CODE_OK !=
                _get_by_raw_pos(
                        type, i, (char *)read_name, USER_NAME_SZ_MAX, read_pubkey, USER_KEY_BUF_SZ_MAX, &key_sz)) {
                VS_LOG_ERROR("Cannot read user data");
                continue;
            }

            if (0 == VS_IOT_STRNCMP(name, (char *)read_name, USER_NAME_SZ_MAX)) {
                *pos = i;
                return VS_CODE_OK;
            }
        }
    }

    return VS_CODE_ERR_USER_NOT_FOUND;
}

/******************************************************************************/
static vs_status_e
_find_by_key(vs_user_type_t type, const vs_pubkey_dated_t *pubkey, uint16_t *pos) {
    vs_status_e ret_code;
    int i;
    uint8_t read_name[USER_NAME_SZ_MAX];
    uint8_t read_key[USER_KEY_BUF_SZ_MAX];
    uint16_t key_sz;
    vs_pubkey_dated_t *read_pubkey = (vs_pubkey_dated_t *)read_key;
    uint8_t *raw_key_1;
    uint8_t *raw_key_2;

    // Check input parameters
    CHECK_NOT_ZERO_RET(type < VS_USER_TYPE_MAX, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(pubkey, VS_CODE_ERR_ZERO_ARGUMENT);

    // Prepare info about used cells
    STATUS_CHECK_RET(_cache_cells_info(type), "Cannot cache users info");

    for (i = 0; i < USER_COUNT_MAX; i++) {
        if (_users_cells[type][i]) {
            if (VS_CODE_OK !=
                _get_by_raw_pos(
                        type, i, (char *)read_name, USER_NAME_SZ_MAX, read_pubkey, USER_KEY_BUF_SZ_MAX, &key_sz)) {
                VS_LOG_ERROR("Cannot read user data");
                continue;
            }

            raw_key_1 = (uint8_t *)&pubkey->pubkey.meta_and_pubkey[pubkey->pubkey.meta_data_sz];
            raw_key_2 = (uint8_t *)&read_pubkey->pubkey.meta_and_pubkey[read_pubkey->pubkey.meta_data_sz];
            size_t key_sz = vs_secmodule_get_pubkey_len(pubkey->pubkey.ec_type);
            if (0 == VS_IOT_MEMCMP(raw_key_1, raw_key_2, key_sz)) {
                *pos = i;
                return VS_CODE_OK;
            }
        }
    }

    return VS_CODE_ERR_USER_NOT_FOUND;
}

/******************************************************************************/
static vs_status_e
_find_raw_pos(vs_user_type_t type, uint16_t pos, uint16_t *raw_pos) {
    vs_status_e ret_code;
    int i, cnt;

    // Check input parameters
    CHECK_NOT_ZERO_RET(type < VS_USER_TYPE_MAX, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(raw_pos, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(pos < USER_COUNT_MAX, VS_CODE_ERR_INCORRECT_ARGUMENT);

    // Prepare info about used cells
    STATUS_CHECK_RET(_cache_cells_info(type), "Cannot cache users info");

    // Look for requred cell
    for (i = 0, cnt = 0; i < USER_COUNT_MAX; i++) {
        if (_users_cells[type][i]) {
            if (cnt == pos) {
                *raw_pos = i;
                return VS_CODE_OK;
            }
            ++cnt;
        }
    }
    return VS_CODE_ERR_USER_NOT_FOUND;
}

/******************************************************************************/
vs_status_e
vs_users_init(void) {
    vs_status_e ret_code;
    int i;

    for (i = 0; i < VS_USER_TYPE_MAX; i++) {
        STATUS_CHECK_RET(_cache_cells_info((vs_user_type_t)i), "Cannot cache users info %d", i);
    }

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_users_deinit(void) {
    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_users_reset(vs_user_type_t type) {
    vs_status_e ret_code;
    vs_status_e ret_code_tmp;
    uint16_t amount;
    uint16_t i;

    STATUS_CHECK_RET(vs_users_get_amount(type, &amount), "Cannot get users amount");

    ret_code = VS_CODE_OK;
    for (i = 0; i < amount; i++) {
        ret_code_tmp = vs_users_remove_by_num(type, i);
        if (VS_CODE_OK != ret_code_tmp) {
            ret_code = ret_code_tmp;
        }
    }

    return ret_code;
}

/******************************************************************************/
vs_status_e
vs_users_add(vs_user_type_t type, const char *name, const vs_pubkey_dated_t *pubkey) {
    vs_status_e ret_code;
    vs_storage_element_id_t id;
    int i;
    int pos = -1;
    uint16_t pubkey_sz;

    // Check input parameters
    CHECK_NOT_ZERO_RET(type < VS_USER_TYPE_MAX, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(name, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(strnlen(name, USER_NAME_SZ_MAX) < USER_NAME_SZ_MAX, VS_CODE_ERR_TOO_SMALL_BUFFER);
    CHECK_NOT_ZERO_RET(pubkey, VS_CODE_ERR_ZERO_ARGUMENT);

    // Prepare info about used cells
    STATUS_CHECK_RET(_cache_cells_info(type), "Cannot cache users info");

    // Look for an empty cell
    for (i = 0; i < USER_COUNT_MAX; i++) {
        if (!_users_cells[type][i]) {
            pos = i;
            break;
        }
    }
    CHECK_RET(pos >= 0, VS_CODE_ERR_USERS_LIMIT, "Too many users, cannot save a new.");

    // Save user info
    STATUS_CHECK_RET(_create_file_name(type, pos, &id), "Cannot create file name for user file");
    STATUS_CHECK_RET(vs_crypto_hl_dated_key_size(pubkey, &pubkey_sz), "Cannot calculate a size of public key");
    size_t required_size = USER_NAME_SZ_MAX + pubkey_sz;
    VS_LOG_DEBUG("User info size: %u", (unsigned int)required_size);
    uint8_t save_data[required_size];
    VS_IOT_MEMSET(save_data, 0, required_size);
    VS_IOT_STRCPY((char *)save_data, name);
    VS_IOT_MEMCPY(&save_data[USER_NAME_SZ_MAX], (uint8_t *)pubkey, pubkey_sz);
    STATUS_CHECK_RET(vs_secbox_save(VS_SECBOX_SIGNED_AND_ENCRYPTED, id, save_data, required_size),
                     "Cannot save user data");

    // Save a new info about users
    _users_cells[type][pos] = 1;
    STATUS_CHECK_RET(_save_cells_info(type), "Cannot save info about users");

    return ret_code;
}

/******************************************************************************/
vs_status_e
vs_users_remove_by_name(vs_user_type_t type, const char *name) {
    uint16_t pos;
    vs_status_e ret_code;

    CHECK_NOT_ZERO_RET(name, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(type < VS_USER_TYPE_MAX, VS_CODE_ERR_ZERO_ARGUMENT);
    STATUS_CHECK_RET(_cache_cells_info(type), "Cannot cache users info");
    STATUS_CHECK_RET(_find_by_name(type, name, &pos), "Cannot find user");

    return vs_users_remove_by_num(type, pos);
}

/******************************************************************************/
vs_status_e
vs_users_remove_by_key(vs_user_type_t type, const vs_pubkey_dated_t *pubkey) {
    uint16_t pos;
    vs_status_e ret_code;

    CHECK_NOT_ZERO_RET(pubkey, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(type < VS_USER_TYPE_MAX, VS_CODE_ERR_ZERO_ARGUMENT);
    STATUS_CHECK_RET(_cache_cells_info(type), "Cannot cache users info");
    STATUS_CHECK_RET(_find_by_key(type, pubkey, &pos), "Cannot find user");

    return vs_users_remove_by_num(type, pos);
}

/******************************************************************************/
static vs_status_e
_remove_by_raw_pos(vs_user_type_t type, uint16_t pos) {
    vs_status_e ret_code;
    vs_storage_element_id_t id;

    CHECK_RET(pos < USER_COUNT_MAX, VS_CODE_ERR_USERS_LIMIT, "Too many users");
    STATUS_CHECK_RET(_create_file_name(type, pos, &id), "Cannot create file name for user file");
    STATUS_CHECK_RET(vs_secbox_del(id), "Cannot remove user");

    _users_cells[type][pos] = 0;

    STATUS_CHECK_RET(_save_cells_info(type), "Cannot save users info");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_users_remove_by_num(vs_user_type_t type, uint16_t pos) {
    vs_status_e ret_code;
    uint16_t raw_pos;

    STATUS_CHECK_RET(_find_raw_pos(type, pos, &raw_pos), "Cannot find raw position of user");
    STATUS_CHECK_RET(_remove_by_raw_pos(type, raw_pos), "Cannot remove user by raw position");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_users_get_amount(vs_user_type_t type, uint16_t *amount) {
    vs_status_e ret_code;
    int i;

    CHECK_NOT_ZERO_RET(type < VS_USER_TYPE_MAX, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(amount, VS_CODE_ERR_ZERO_ARGUMENT);
    STATUS_CHECK_RET(_cache_cells_info(type), "Cannot cache users info");

    *amount = 0;

    for (i = 0; i < USER_COUNT_MAX; i++) {
        if (_users_cells[type][i]) {
            *amount += 1;
        }
    }

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_users_get_by_num(vs_user_type_t type,
                    uint16_t pos,
                    char *name,
                    uint16_t name_buf_sz,
                    vs_pubkey_dated_t *pubkey,
                    uint16_t key_buf_sz,
                    uint16_t *key_sz) {
    vs_status_e ret_code;
    uint16_t raw_pos;

    STATUS_CHECK_RET(_find_raw_pos(type, pos, &raw_pos), "Cannot find raw position of user");
    STATUS_CHECK_RET(_get_by_raw_pos(type, raw_pos, name, name_buf_sz, pubkey, key_buf_sz, key_sz),
                     "Cannot get user info by raw position");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_users_get_key(vs_user_type_t type, const char *name, vs_pubkey_dated_t *pubkey, uint16_t buf_sz, uint16_t *key_sz) {
    uint16_t pos;
    vs_status_e ret_code;
    uint8_t read_name[USER_NAME_SZ_MAX];

    CHECK_NOT_ZERO_RET(name, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(type < VS_USER_TYPE_MAX, VS_CODE_ERR_ZERO_ARGUMENT);
    STATUS_CHECK_RET(_cache_cells_info(type), "Cannot cache users info");
    STATUS_CHECK_RET(_find_by_name(type, name, &pos), "Cannot find user");

    // TODO: improve speed by one read instead of two
    return _get_by_raw_pos(type, pos, (char *)read_name, USER_NAME_SZ_MAX, pubkey, buf_sz, key_sz);
}

/******************************************************************************/
vs_status_e
vs_users_get_name(vs_user_type_t type, const vs_pubkey_dated_t *pubkey, char *name, uint16_t buf_sz) {
    uint16_t pos;
    vs_status_e ret_code;
    uint8_t read_key[USER_KEY_BUF_SZ_MAX];
    uint16_t key_sz;

    CHECK_NOT_ZERO_RET(pubkey, VS_CODE_ERR_ZERO_ARGUMENT);
    CHECK_NOT_ZERO_RET(type < VS_USER_TYPE_MAX, VS_CODE_ERR_ZERO_ARGUMENT);
    STATUS_CHECK_RET(_cache_cells_info(type), "Cannot cache users info");
    STATUS_CHECK_RET(_find_by_key(type, pubkey, &pos), NULL);

    // TODO: improve speed by one read instead of two
    return _get_by_raw_pos(type, pos, name, buf_sz, (vs_pubkey_dated_t *)read_key, USER_KEY_BUF_SZ_MAX, &key_sz);
}

/******************************************************************************/
