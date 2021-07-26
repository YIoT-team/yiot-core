#!/bin/bash

SCRIPT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source ${SCRIPT_PATH}/inc/options.sh

############################################################################################
check_error() {
   RETRES=$?
   if [ $RETRES != 0 ]; then
        echo "----------------------------------------------------------------------"
        echo "############# !!! PROCESS ERROR ERRORCODE=[$RETRES] ##################"
        echo "----------------------------------------------------------------------"
     exit $RETRES
   else
        echo "-------------Process OK. ---------------------------------------------"
   fi
}

############################################################################################
echo_info() {
echo "--- Package version"
echo "MAJOR=$MAJOR_VER"
echo "MINOR=$MINOR_VER"
echo "SUB  =$SUB_VER"
echo "BUILD=$BUILD_VER"
echo "--- "
}

############################################################################################
create_dirs() {
 echo "Remove old dirs and create new"
 rm -rf ${BUILD_PATH} | true
 mkdir -p ${BUILD_PATH}/${PKG_SRC_NAME}
 check_error
}

############################################################################################
create_srpm() {
 pushd ${BUILD_PATH}
  mkdir -p srpm
  echo "------------- Create SPEC from template ------------------------------"
  cp -f ${PROJECT_PATH}/src/srpm/* srpm
  check_error
 popd
}



############################################################################################
echo_info
create_dirs
create_srpm

echo "------ END PREPARING SRPMS"
exit 0
