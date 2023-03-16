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

#ifndef VS_IOT_LICENSE_H
#define VS_IOT_LICENSE_H

#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/provision/provision-structs.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/storage_hal/storage_hal.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

#define VS_LICENSE_DATA_MAX_SZ (10 * 1024)
#define VS_LICENSE_SIGN_MAX_SZ (1024)
#define VS_LICENSE_KEY_MAX_SZ (512)

/** License initialization
 *
 * This function must be called before any other License call.
 *
 * \param[in] secmodule Security Module implementation. Must not be NULL.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_license_init(vs_secmodule_impl_t *secmodule/*, vs_license_events_t events_cb*/);

/** Parse signed license
*
* This function gets pointers to License data and signature
*
* \param[in] license_buf Signed License. Must not be NULL.
* \param[in] buf_sz Size of a license
* \param[out] data_buf Buffer for a license data.
* \param[in] data_buf_sz Size of a buffer for a license data.
* \param[out] data_sz Size of license data.
* \param[out] sign Buffer for a signature.
* \param[in] sign_buf_sz Size of a buffer for a signature data.
* \param[out] sign_sz Size of signature data.
*
* \return #VS_CODE_OK in case of success or error code.
*
 */
vs_status_e
vs_license_parse(uint8_t *license_buf, uint16_t license_sz,
                 char *data_buf, uint16_t data_buf_sz, uint16_t *data_sz,
                 char *sign_buf, uint16_t sign_buf_sz, uint16_t *sign_sz);

/** Get License plain data
*
* This function gets license plain data without base64
*
* \param[in] license_buf Signed License. Must not be NULL.
* \param[in] buf_sz Size of a license
* \param[out] data_buf Buffer for a license data.
* \param[in] data_buf_sz Size of a buffer for a license data.
* \param[out] data_sz Size of license data.
*
* \return #VS_CODE_OK in case of success or error code.
*
 */
vs_status_e
vs_license_plain_data(uint8_t *license_buf, uint16_t license_sz,
                 char *data_buf, uint16_t data_buf_sz, uint16_t *data_sz);

/** Verify license
*
* This function verifies license in buffer
*
* \param[in] license_buf License. Must not be NULL.
* \param[in] buf_sz Size of a license
*
* \return #VS_CODE_OK in case of success verification or error code.
*
*/
vs_status_e
vs_license_verify(uint8_t *license_buf, uint16_t license_sz);

/** Check if license content matches required data
*
* Parse license data and compare: public key, mac address, serial number, manufacturer and model
*
* \param[in] license_buf License. Must not be NULL.
* \param[in] buf_sz Size of a license
* \param[in] raw_pubkey Raw Public Key
* \param[in] raw_pubkey_sz Raw Public Key size
* \param[in] mac_addr MAC address
* \param[in] serial_number Serial number
* \param[in] manufacturer Manufacturer
* \param[in] model Model
*
* \return #VS_CODE_OK in case of success comparing or error code.
*
 */
vs_status_e
vs_license_matches(uint8_t *license, uint16_t license_sz,
                   uint8_t *raw_pubkey, uint16_t raw_pubkey_sz,
                   vs_mac_addr_t mac_addr,
                   vs_device_serial_t serial_number,
                   vs_device_manufacture_id_t manufacturer,
                   vs_device_type_t model);

/** Get verified license
*
* This function loads license if present, and verifies signatures
*
* \param[out] license_buf Buffer to copy license. Must not be NULL.
* \param[in] buf_sz Size of a buffer for a license
* \param[out] license_sz License information size. Must not be NULL.
*
* \return #VS_CODE_OK in case of success or error code.
*
*/
vs_status_e
vs_license_get(uint8_t *license_buf, uint16_t buf_sz, uint16_t *license_sz);

/** Save license
*
* This function verifies and saves license
*
* \param[in] license_buf License. Must not be NULL.
* \param[in] buf_sz Size of a license
*
* \return #VS_CODE_OK in case of success or error code.
*
*/
vs_status_e
vs_license_save(uint8_t *license_buf, uint16_t license_sz);

/** Parse all license data
*
* \return #VS_CODE_OK in case of success or error code.
*
 */
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
                            char *extra_data_buf, uint16_t extra_data_buf_sz, uint16_t *extra_data_sz);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_IOT_LICENSE_H