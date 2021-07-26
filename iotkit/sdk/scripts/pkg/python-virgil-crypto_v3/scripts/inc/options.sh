
#PROJECT_BRANCH="${PROJECT_BRANCH:-v3}"
PROJECT_BRANCH="v3"

#PROJECT_BRANCH1="${PROJECT_BRANCH1:-v2.6.3}"
PROJECT_BRANCH1="v2.6.3"

DEB_PROJECTS_BUILD="${DEB_PROJECTS_BUILD:-"Raspbian_10 Raspbian_9 Ubuntu_18 Ubuntu_19"}"
RPM_PROJECTS_BUILD="${RPM_PROJECTS_BUILD:-"Fedora_29 Fedora_30 Fedora_31"}"

###############################################################################
PROJECT_PATH="$(readlink -f "${SCRIPT_PATH}/../")"
BUILD_PATH="${SCRIPT_PATH}/../build/"
OSC_PATH="${BUILD_PATH}/OSC/"
SRPM_PATH="${BUILD_PATH}/srpm"
SDEB_PATH="${BUILD_PATH}/sdeb"

VERSION_FILE="${PROJECT_PATH}/VERSION"

export PACKAGE_NAME=${PACKAGE_NAME:-"python-virgil-crypto"}

if [ -f "$VERSION_FILE" ]; then
  export MAJOR_VER=$(cat "$VERSION_FILE"| cut -d'.' -f1)
  export MINOR_VER=$(cat "$VERSION_FILE"| cut -d'.' -f2)
  export SUB_VER=$(cat "$VERSION_FILE"| cut -d'.' -f3)
fi

export MAJOR_VER=${MAJOR_VER:-"0"}
export MINOR_VER=${MINOR_VER:-"0"}
export SUB_VER=${SUB_VER:-"0"}
export BUILD_VER=${BUILD_VER:-"1"}

GET_SOURCE0="git clone --branch ${PROJECT_BRANCH} --single-branch https://github.com/VirgilSecurity/virgil-crypto-python.git"
GET_SOURCE1="git clone --branch ${PROJECT_BRANCH1} --single-branch https://github.com/VirgilSecurity/virgil-crypto.git"

PKG_SRC_NAME="${PACKAGE_NAME}-$MAJOR_VER.$MINOR_VER.$SUB_VER"

[ "${DEB_PROJECTS_BUILD}" == "NONE" ] && DEB_PROJECTS_BUILD=""
[ "${RPM_PROJECTS_BUILD}" == "NONE" ] && RPM_PROJECTS_BUILD=""

PROJECTS_BUILD="${RPM_PROJECTS_BUILD} ${DEB_PROJECTS_BUILD}"

TYPE_BUILD="${TYPE_BUILD:-"testing"}"
CHANGELOG_TEXT="${CHANGELOG_TEXT:-"Automatic rebuild"}"
