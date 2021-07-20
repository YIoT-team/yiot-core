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
get_sources() {
 pushd ${BUILD_PATH}
  echo "Download #1 [${GET_SOURCE0}]"
  ${GET_SOURCE0} ${PKG_SRC_NAME}
  check_error

  echo "Download #2 [${GET_SOURCE1}]" 
  ${GET_SOURCE1} ${PKG_SRC_NAME}/ext/virgil-crypto
  check_error
 popd 
 
 pushd ${BUILD_PATH}/${PKG_SRC_NAME}/ext/virgil-crypto
   echo "Download depend cache"
   mkdir -p build
   cd build
   cmake ..
   cd ..
   rm -rf build
   check_error
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
  tar czf srpm/${PKG_SRC_NAME}.tgz ${PKG_SRC_NAME}
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
  tar czf sdeb/${PACKAGE_NAME}_${MAJOR_VER}.${MINOR_VER}.${SUB_VER}.orig.tar.gz ${PKG_SRC_NAME}
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