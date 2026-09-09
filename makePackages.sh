#!/bin/sh
#
#    Procmon for Linux
#
#    Copyright (c) Microsoft Corporation
#
#    All rights reserved.
#
#    MIT License
#
#    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
#    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
#    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

#################################################################################
#
# makePackages.sh
#
# Builds the directory trees for DEB and RPM packages and, if suitable tools are
# available, builds the actual packages too.
#
#################################################################################

if [ "$5" = "" ]; then
    echo "Usage: $0 <SourceDir> <BinaryDir> <package name> <package version> <package release> <PackageType>"
    exit 1
fi

# copy cmake vars
CMAKE_SOURCE_DIR=$1
PROJECT_BINARY_DIR=$2
PACKAGE_NAME=$3
PACKAGE_VER=$4
PACKAGE_REL=$5
PACKAGE_TYPE=$6

RPM_PACKAGE_NAME="${PACKAGE_NAME}-${PACKAGE_VER}-${PACKAGE_REL}"

if [ "$PACKAGE_TYPE" = "deb" ]; then
    # Fail on staging errors and propagate dpkg-deb failures to the build job.
    set -e
    DPKGDEB=$(command -v dpkg-deb) || { echo "No dpkg-deb found" >&2; exit 1; }

    # CMake configures the target architecture once in DEBIANcontrol. Use it
    # for the filename too, including when cross-compiling on an x64 host.
    DEB_ARCH=$(sed -n 's/^Architecture: *//p' "${PROJECT_BINARY_DIR}/DEBIANcontrol" | tr -d '\r')
    case "$DEB_ARCH" in
        amd64|arm64) ;;
        *) echo "Unsupported or missing Debian architecture: $DEB_ARCH" >&2; exit 1 ;;
    esac
    DEB_PACKAGE_NAME="${PACKAGE_NAME}_${PACKAGE_VER}_${DEB_ARCH}"

    if [ -d "${PROJECT_BINARY_DIR}/deb" ]; then
        rm -rf "${PROJECT_BINARY_DIR}/deb"
    fi

    # copy deb files
    mkdir -p "${PROJECT_BINARY_DIR}/deb/${DEB_PACKAGE_NAME}"
    #cp -a "${CMAKE_SOURCE_DIR}/dist/DEBIAN" "${PROJECT_BINARY_DIR}/deb/${DEB_PACKAGE_NAME}/"
    mkdir -p "${PROJECT_BINARY_DIR}/deb/${DEB_PACKAGE_NAME}/DEBIAN"
    cp "${PROJECT_BINARY_DIR}/DEBIANcontrol" "${PROJECT_BINARY_DIR}/deb/${DEB_PACKAGE_NAME}/DEBIAN/control"
    mkdir -p "${PROJECT_BINARY_DIR}/deb/${DEB_PACKAGE_NAME}/usr/share/doc/procmon"
    cp "${PROJECT_BINARY_DIR}/changelog.gz" "${PROJECT_BINARY_DIR}/deb/${DEB_PACKAGE_NAME}/usr/share/doc/procmon"
    mkdir -p "${PROJECT_BINARY_DIR}/deb/${DEB_PACKAGE_NAME}/usr/share/man/man1"
    cp -a "${PROJECT_BINARY_DIR}/procmon.1.gz" "${PROJECT_BINARY_DIR}/deb/${DEB_PACKAGE_NAME}/usr/share/man/man1"
    mkdir -p "${PROJECT_BINARY_DIR}/deb/${DEB_PACKAGE_NAME}/usr/bin"
    cp "${PROJECT_BINARY_DIR}/procmon" "${PROJECT_BINARY_DIR}/deb/${DEB_PACKAGE_NAME}/usr/bin/"

    # make the deb
    cd "${PROJECT_BINARY_DIR}/deb"
    "$DPKGDEB" -Zxz --build --root-owner-group "${DEB_PACKAGE_NAME}"
    exit $?
fi

if [ "$PACKAGE_TYPE" = "rpm" ]; then
    RPMBUILD=`which rpmbuild`

    if [ -d "${PROJECT_BINARY_DIR}/rpm" ]; then
        rm -rf "${PROJECT_BINARY_DIR}/rpm"
    fi

    # copy rpm files
    mkdir -p "${PROJECT_BINARY_DIR}/rpm/${RPM_PACKAGE_NAME}/SPECS"
    cp -a "${PROJECT_BINARY_DIR}/SPECS.spec" "${PROJECT_BINARY_DIR}/rpm/${RPM_PACKAGE_NAME}/SPECS/${RPM_PACKAGE_NAME}.spec"
    mkdir "${PROJECT_BINARY_DIR}/rpm/${RPM_PACKAGE_NAME}/BUILD/"
    cp "${PROJECT_BINARY_DIR}/procmon.1.gz" "${PROJECT_BINARY_DIR}/changelog" "${PROJECT_BINARY_DIR}/procmon" "${PROJECT_BINARY_DIR}/rpm/${RPM_PACKAGE_NAME}/BUILD/"

    # make the rpm
    if [ "$RPMBUILD" != "" ]; then
        cd "${PROJECT_BINARY_DIR}/rpm/${RPM_PACKAGE_NAME}"
        "$RPMBUILD" --define "_topdir `pwd`" -v -bb "SPECS/${RPM_PACKAGE_NAME}.spec"
        RET=$?
        if [ "$RET" -eq 0 ]; then
            RPM_ARCH=`"$RPMBUILD" --eval '%{_arch}'`
            cp "RPMS/${RPM_ARCH}/"*.rpm ..
            RET=$?
        fi
    else
        echo "No rpmbuild found"
        RET=1
    fi
fi

exit $RET
