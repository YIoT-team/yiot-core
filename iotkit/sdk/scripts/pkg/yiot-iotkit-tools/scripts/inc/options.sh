
PROJECT_BRANCH="${PROJECT_BRANCH:-feature/name}"
#PROJECT_BRANCH="${PROJECT_BRANCH:-dev/esp32}"

DEB_PROJECTS_BUILD="${DEB_PROJECTS_BUILD:-"Raspbian_10 Raspbian_9 Ubuntu_18 Ubuntu_19"}"
RPM_PROJECTS_BUILD="${RPM_PROJECTS_BUILD:-"Fedora_29 Fedora_30 Fedora_31"}"

######################################################################
PROJECT_PATH="$(readlink -f "${SCRIPT_PATH}/../")"
BUILD_PATH="${SCRIPT_PATH}/../build/"
OSC_PATH="${BUILD_PATH}/OSC/"
SRPM_PATH="${BUILD_PATH}/srpm"
SDEB_PATH="${BUILD_PATH}/sdeb"

VERSION_FILE="${PROJECT_PATH}/VERSION"
SDKVERSION_FILE="${PROJECT_PATH}/sdk/VERSION"

######################################################################
export PACKAGE_NAME=${PACKAGE_NAME:-"yiot-iotkit-tools"}

export MAJOR_VER=${MAJOR_VER:-"0"}
export MINOR_VER=${MINOR_VER:-"0"}
export SUB_VER=${SUB_VER:-"0"}
export BUILD_VER=${BUILD_VER:-"1"}

#GET_SOURCE0="git clone --branch ${PROJECT_BRANCH} --single-branch --recurse-submodules https://github.com/VirgilSecurity/virgil-iotkit.git"
GET_SOURCE0="git clone --branch ${PROJECT_BRANCH} --single-branch --recurse-submodules https://github.com/kutashenko/virgil-iotkit.git"

PKG_SRC_NAME="${PACKAGE_NAME}-$MAJOR_VER.$MINOR_VER.$SUB_VER"

[ "${DEB_PROJECTS_BUILD}" == "NONE" ] && DEB_PROJECTS_BUILD=""
[ "${RPM_PROJECTS_BUILD}" == "NONE" ] && RPM_PROJECTS_BUILD=""

PROJECTS_BUILD="${RPM_PROJECTS_BUILD} ${DEB_PROJECTS_BUILD}" 

TYPE_BUILD="${TYPE_BUILD:-"testing"}"
CHANGELOG_TEXT="${CHANGELOG_TEXT:-"Automatic rebuild"}"
