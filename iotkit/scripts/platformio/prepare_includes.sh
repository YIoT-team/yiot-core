#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BASE_DIR="${SCRIPT_FOLDER}/../.."
INC_DIR="${BASE_DIR}/_pio_include/virgil/iot"
SRC_DIR="${BASE_DIR}/sdk"

rm -rf ${INC_DIR}      || true
mkdir -p ${INC_DIR}

cp -rf ${SRC_DIR}/modules/firmware/include/virgil/iot/firmware                                     ${INC_DIR}
cp -rf ${SRC_DIR}/modules/logger/include/virgil/iot/logger                                         ${INC_DIR}
cp -rf ${SRC_DIR}/modules/protocols/snap/include/virgil/iot/protocols                              ${INC_DIR}
cp -rf ${SRC_DIR}/modules/provision/include/virgil/iot/provision                                   ${INC_DIR}
cp -rf ${SRC_DIR}/modules/provision/trust_list/include/virgil/iot/trust_list                       ${INC_DIR}
cp -rf ${SRC_DIR}/modules/crypto/secmodule/include/virgil/iot/secmodule                            ${INC_DIR}
cp -rf ${SRC_DIR}/modules/crypto/session/include/virgil/iot/session                                ${INC_DIR}
cp -rf ${SRC_DIR}/modules/users/include/virgil/iot/users                                           ${INC_DIR}
cp -rf ${SRC_DIR}/modules/secbox/include/virgil/iot/secbox                                         ${INC_DIR}

cp -rf ${SRC_DIR}/default-impl/crypto/vs-soft-secmodule/include/virgil/iot/vs-soft-secmodule       ${INC_DIR}
cp -rf ${SRC_DIR}/helpers/status_code/include/virgil/iot/status_code                               ${INC_DIR}
cp -rf ${SRC_DIR}/helpers/macros/include/virgil/iot/macros                                         ${INC_DIR}
