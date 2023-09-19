#!/bin/bash
#  ────────────────────────────────────────────────────────────
#                     ╔╗  ╔╗ ╔══╗      ╔════╗
#                     ║╚╗╔╝║ ╚╣╠╝      ║╔╗╔╗║
#                     ╚╗╚╝╔╝  ║║  ╔══╗ ╚╝║║╚╝
#                      ╚╗╔╝   ║║  ║╔╗║   ║║
#                       ║║   ╔╣╠╗ ║╚╝║   ║║
#                       ╚╝   ╚══╝ ╚══╝   ╚╝
#    ╔╗╔═╗                    ╔╗                     ╔╗
#    ║║║╔╝                   ╔╝╚╗                    ║║
#    ║╚╝╝  ╔══╗ ╔══╗ ╔══╗  ╔╗╚╗╔╝  ╔══╗ ╔╗ ╔╗╔╗ ╔══╗ ║║  ╔══╗
#    ║╔╗║  ║║═╣ ║║═╣ ║╔╗║  ╠╣ ║║   ║ ═╣ ╠╣ ║╚╝║ ║╔╗║ ║║  ║║═╣
#    ║║║╚╗ ║║═╣ ║║═╣ ║╚╝║  ║║ ║╚╗  ╠═ ║ ║║ ║║║║ ║╚╝║ ║╚╗ ║║═╣
#    ╚╝╚═╝ ╚══╝ ╚══╝ ║╔═╝  ╚╝ ╚═╝  ╚══╝ ╚╝ ╚╩╩╝ ║╔═╝ ╚═╝ ╚══╝
#                    ║║                         ║║
#                    ╚╝                         ╚╝
#
#    Lead Maintainer: Roman Kutashenko <kutashenko@gmail.com>
#  ────────────────────────────────────────────────────────────

set -e
SCRIPT_PATH="$(cd $(dirname "$0") >/dev/null 2>&1 && pwd)"
source ${SCRIPT_PATH}/SETTINGS
RESULT_DIR="${SCRIPT_PATH}/result"

#######################################################################################################################
echo_title() {
  echo "#========================"
  echo "#= ${@}"
  echo "#========================"
}


#######################################################################################################################
create_dir() {
  rm -rf ${RESULT_DIR}
  mkdir -p ${RESULT_DIR}
}

#######################################################################################################################
clean_mock() {
   sudo mock -r ${BUILD_OS_DISTR} --init
}


#######################################################################################################################
build_rpm() {
   
   local PARAM_PACKAGE="${1}"
   echo_title "Build RPM: ${PARAM_PACKAGE}"
   pushd ${SCRIPT_PATH}/${PARAM_PACKAGE}
      scripts/prep-src.sh
      pushd ${SCRIPT_PATH}/${PARAM_PACKAGE}/build/srpm
          sudo mock -n -N -r ${BUILD_OS_DISTR} --buildsrpm --enable-network --resultdir=./ --spec *.spec --sources ./
          sudo mock -n -N -r ${BUILD_OS_DISTR} *.src.rpm --enable-network --resultdir=./
          INST_PKG="$(ls *.rpm | grep -v '.src.rpm')"
          sudo mock -n -N -r ${BUILD_OS_DISTR} -i ${INST_PKG}
          cp *.rpm ${RESULT_DIR}
      popd
      rm -rf ${SCRIPT_PATH}/${PARAM_PACKAGE}/build
   popd
}

#######################################################################################################################
create_dir
clean_mock
build_rpm python-PyCRC
build_rpm python-tinydb
build_rpm python-virgil-crypto_v3
build_rpm python-virgil-sdk
build_rpm yiot-iotkit-tools

