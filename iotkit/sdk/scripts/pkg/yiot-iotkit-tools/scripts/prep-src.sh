#!/bin/bash

set -e

SCRIPT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
IOTKIT_PROJECT_PATH="${SCRIPT_PATH}/../../../../"
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
echo "BRANCH=$PROJECT_BRANCH"
echo "MAJOR=$MAJOR_VER"
echo "MINOR=$MINOR_VER"
echo "SUB  =$SUB_VER"
echo "BUILD=$BUILD_VER"
echo "--- "
}

############################################################################################
rewrite_version() {
  SDKVERSION_FILE="${BUILD_PATH}/${PACKAGE_NAME}/sdk/VERSION"
  if [ -f "$SDKVERSION_FILE" ]; then
    export MAJOR_VER=$(cat "$SDKVERSION_FILE"| cut -d'.' -f1)
    export MINOR_VER=$(cat "$SDKVERSION_FILE"| cut -d'.' -f2)
    export SUB_VER=$(cat "$SDKVERSION_FILE"| cut -d'.' -f3)
    echo "New version file found."
    echo_info 
  fi
}

############################################################################################
create_dirs() {
 echo "Remove old dirs and create new"
 rm -rf ${BUILD_PATH} | true
 mkdir -p ${BUILD_PATH}/${PACKAGE_NAME}
 check_error
}

############################################################################################
get_sources() {
 pushd ${BUILD_PATH}/${PACKAGE_NAME}
#   echo "Download [${GET_SOURCE0}]"
#   ${GET_SOURCE0} ${BUILD_PATH}/${PACKAGE_NAME}
   mkdir -p ${BUILD_PATH}/${PACKAGE_NAME}
   rsync -v -ram --exclude='scripts' "${IOTKIT_PROJECT_PATH}/" "${BUILD_PATH}/${PACKAGE_NAME}"
 popd   

 rewrite_version
 mv ${BUILD_PATH}/${PACKAGE_NAME} ${BUILD_PATH}/${PACKAGE_NAME}-$MAJOR_VER.$MINOR_VER.$SUB_VER

 pushd ${BUILD_PATH}/${PACKAGE_NAME}-$MAJOR_VER.$MINOR_VER.$SUB_VER
   check_error
   echo "####################"   
   echo "# Download cache"
   echo "####################"      
   cmake3  -Bbuild -H. -DVIRGIL_IOT_CONFIG_DIRECTORY="$(pwd)/config/pc"
   rm -rf build
   mkdir -p build
   check_error
   
   git clone https://github.com/gorilla/websocket.git                                   build/go/src/github.com/gorilla/websocket
   check_error
   git clone https://github.com/pkg/errors                                              build/go/src/github.com/pkg/errors   
   check_error
   git clone https://gopkg.in/urfave/cli.v2                                             build/go/src/gopkg.in/urfave/cli.v2
   check_error
   git clone https://gopkg.in/virgil.v5                                                 build/go/src/gopkg.in/virgil.v5   
   check_error
   git clone --branch=v2.0.0 https://github.com/cpuguy83/go-md2man                      build/go/src/github.com/cpuguy83/go-md2man
   check_error
   mkdir -p  build/go/src/github.com/cpuguy83/go-md2man/v2/
   ln -s ../md2man  build/go/src/github.com/cpuguy83/go-md2man/v2/md2man
   git clone https://gopkg.in/virgilsecurity/virgil-crypto-go.v5                        build/go/src/gopkg.in/virgilsecurity/virgil-crypto-go.v5
   check_error
   git clone --branch=master https://github.com/VirgilSecurity/virgil-crypto.git        build/go/src/gopkg.in/virgilsecurity/virgil-crypto-go.v5/ext/virgil-crypto
   check_error
   rm -f build/go/src/gopkg.in/virgilsecurity/virgil-crypto-go.v5/Makefile
   pushd build/go/src/gopkg.in/virgilsecurity/virgil-crypto-go.v5/ext/virgil-crypto
     cmake -H. -B_build -DCMAKE_INSTALL_PREFIX=../../ -DLANG=go -DINSTALL_CORE_LIBS=ON; rm -rf _build
   popd

 popd    
}

############################################################################################
create_srpm() {
 pushd ${BUILD_PATH}
  mkdir -p srpm
  echo "------------- Create SPEC from template ------------------------------"         
  j2 -f env -o srpm/${PACKAGE_NAME}.spec ${PROJECT_PATH}/tmpl/rpm/${PACKAGE_NAME}.spec.in
  check_error 
  echo "------------- Create archive  ------------------------------"          
  tar czf srpm/${PACKAGE_NAME}-$MAJOR_VER.$MINOR_VER.$SUB_VER.tgz ${PACKAGE_NAME}-$MAJOR_VER.$MINOR_VER.$SUB_VER
  check_error  
 popd
}

############################################################################################
create_sdeb() {
 pushd ${BUILD_PATH}
  mkdir -p sdeb
  echo "------------- Create DEB from template ------------------------------"         
  tar xJf ../tmpl/deb/${PACKAGE_NAME}.debian.tar.xz
  check_error   
  j2 -f env -o sdeb/${PACKAGE_NAME}_${MAJOR_VER}.${MINOR_VER}.${SUB_VER}-${BUILD_VER}.dsc ../tmpl/deb/${PACKAGE_NAME}.dsc.tmpl
  check_error   
  j2 -f env -o debian/changelog debian/changelog
  check_error   
  tar cJf sdeb/${PACKAGE_NAME}_${MAJOR_VER}.${MINOR_VER}.${SUB_VER}-${BUILD_VER}.debian.tar.xz debian
  rm -rf debian
  echo "------------- Create archive for SDEB  ------------------------------"          
  tar czf sdeb/${PACKAGE_NAME}_${MAJOR_VER}.${MINOR_VER}.${SUB_VER}.orig.tar.gz ${PACKAGE_NAME}-$MAJOR_VER.$MINOR_VER.$SUB_VER
  check_error  
  pushd sdeb
  echo "------------- Create checksum for DEB  ------------------------------"            
  file_dsc=${PACKAGE_NAME}_${MAJOR_VER}.${MINOR_VER}.${SUB_VER}-${BUILD_VER}.dsc
  file_deb_name=${PACKAGE_NAME}_${MAJOR_VER}.${MINOR_VER}.${SUB_VER}-${BUILD_VER}.debian.tar.xz
  file_src_name=${PACKAGE_NAME}_${MAJOR_VER}.${MINOR_VER}.${SUB_VER}.orig.tar.gz

  file_deb_size=$(stat --printf="%s" "$file_deb_name")
  file_src_size=$(stat --printf="%s" "$file_src_name")

  file_sha1_src_hash=$(sha1sum "$file_src_name" | cut -f1 -d ' ')
  file_sha256_src_hash=$(sha256sum "$file_src_name" | cut -f1 -d ' ')
  file_md5_src_hash=$(md5sum "$file_src_name" | cut -f1 -d ' ')

  file_sha1_deb_hash=$(sha1sum "$file_deb_name" | cut -f1 -d ' ')
  file_sha256_deb_hash=$(sha256sum "$file_deb_name" | cut -f1 -d ' ')
  file_md5_deb_hash=$(md5sum "$file_deb_name" | cut -f1 -d ' ')

  echo "Checksums-Sha1:" >> $file_dsc
  echo " $file_sha1_src_hash $file_src_size $file_src_name"  >> $file_dsc
  echo " $file_sha1_deb_hash $file_deb_size $file_deb_name"  >> $file_dsc

  echo "Checksums-Sha256:" >> $file_dsc
  echo " $file_sha256_src_hash $file_src_size $file_src_name"  >> $file_dsc
  echo " $file_sha256_deb_hash $file_deb_size $file_deb_name"  >> $file_dsc

  echo "Files:" >> $file_dsc
  echo " $file_md5_src_hash $file_src_size $file_src_name"  >> $file_dsc
  echo " $file_md5_deb_hash $file_deb_size $file_deb_name"  >> $file_dsc
  check_error  
  popd
 popd
}

############################################################################################
 echo_info
 create_dirs

pushd ${BUILD_PATH} 
 get_sources
 create_srpm
 create_sdeb
popd
echo "------ END PREPARING SRPMS"
exit 0
