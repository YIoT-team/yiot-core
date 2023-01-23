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
#include <virgil/iot/provision/provision-structs.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/storage_hal/storage_hal.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

#define VS_LICENSE_DATA_MAX_SZ (4 * 1024)
#define VS_LICENSE_SIGN_MAX_SZ (1024)

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

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_IOT_LICENSE_H