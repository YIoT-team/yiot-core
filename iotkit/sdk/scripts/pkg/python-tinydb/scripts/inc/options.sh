
DEB_PROJECTS_BUILD="${DEB_PROJECTS_BUILD:-"Raspbian_10 Raspbian_9 Ubuntu_18 Ubuntu_19"}"
RPM_PROJECTS_BUILD="${RPM_PROJECTS_BUILD:-NONE}"

######################################################################

PROJECT_PATH="$(readlink -f "${SCRIPT_PATH}/../")"
BUILD_PATH="${SCRIPT_PATH}/../build/"
OSC_PATH="${BUILD_PATH}/OSC/"
SRPM_PATH="${PROJECT_PATH}/src/srpm"
SDEB_PATH="${PROJECT_PATH}/src/sdeb"

VERSION_FILE="${PROJECT_PATH}/VERSION"

export RPM_PACKAGE_NAME=${PACKAGE_NAME:-"python-tinydb"}
export DEB_PACKAGE_NAME=${PACKAGE_NAME:-"python-tinydb"}
export PACKAGE_NAME=${PACKAGE_NAME:-"python-tinydb"}

if [ -f "$VERSION_FILE" ]; then
  export MAJOR_VER=$(cat "$VERSION_FILE"| cut -d'.' -f1)
  export MINOR_VER=$(cat "$VERSION_FILE"| cut -d'.' -f2)
  export SUB_VER=$(cat "$VERSION_FILE"| cut -d'.' -f3)
fi

export MAJOR_VER=${MAJOR_VER:-"0"}
export MINOR_VER=${MINOR_VER:-"0"}
export SUB_VER=${SUB_VER:-"0"}
export BUILD_VER=${BUILD_VER:-"1"}

PKG_SRC_NAME="${PACKAGE_NAME}-$MAJOR_VER.$MINOR_VER.$SUB_VER"

[ "${DEB_PROJECTS_BUILD}" == "NONE" ] && DEB_PROJECTS_BUILD=""
[ "${RPM_PROJECTS_BUILD}" == "NONE" ] && RPM_PROJECTS_BUILD=""

PROJECTS_BUILD="${RPM_PROJECTS_BUILD} ${DEB_PROJECTS_BUILD}"

TYPE_BUILD="${TYPE_BUILD:-"testing"}"
CHANGELOG_TEXT="${CHANGELOG_TEXT:-"Automatic rebuild"}"
