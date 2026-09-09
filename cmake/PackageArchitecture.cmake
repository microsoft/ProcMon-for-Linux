# Use the compiler target, not the build host, for Debian package metadata.
string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" PACKAGE_PROCESSOR)
if(PACKAGE_PROCESSOR MATCHES "^(x86_64|amd64)$")
    set(DEB_ARCH "amd64")
elseif(PACKAGE_PROCESSOR MATCHES "^(aarch64|arm64)$")
    set(DEB_ARCH "arm64")
else()
    message(FATAL_ERROR "Unsupported package architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()