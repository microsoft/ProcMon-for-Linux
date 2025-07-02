# Build
Please see the history of this file for instructions for older, unsupported versions.

## Prerequisites
- SysinternalsEBPF being installed:
library `libsysinternalsEBPF.so`, header `libsysinternalsEBPF.h`, plus
resource files in `/opt/sysinternalsEBPF`. These can be installed from
the
[SysinternalsEBPF](https://github.com/Sysinternals/SysinternalsEBPF)
project or via the `sysinternalsebpf` DEB package from the
_packages.microsoft.com_ repository (see [INSTALL.md](INSTALL.md)).
If you installed SysinternalsEBPF via make install, you may need to add /usr/local/lib to the loader library path (LD_LIBRARY_PATH).

- clang/llvm v10+

### Azure Linux
```
sudo dnf update
sudo dnf install gcc gcc-c++ make cmake llvm clang elfutils-libelf-devel rpm-build json-glib-devel python3 libxml2-devel openssl-devel ncurses-devel
```

### Ubuntu 20.04+
```
sudo apt update
sudo apt -y install build-essential gcc g++ make cmake libelf-dev llvm clang libxml2 libxml2-dev libzstd1 git libgtest-dev apt-transport-https dirmngr libjson-glib-dev libssl-dev
```

### Rocky 9
```
sudo dnf install dnf-plugins-core
sudo dnf config-manager --set-enabled crb
sudo dnf install epel-release

sudo dnf update
sudo yum install gcc gcc-c++ make cmake llvm clang elfutils-libelf-devel rpm-build json-glib-devel python3 libxml2-devel openssl-devel ncurses-devel
```

### Rocky 8
```
sudo dnf install dnf-plugins-core
sudo dnf install epel-release
sudo dnf config-manager --set-enabled powertools

sudo dnf update
sudo yum install gcc gcc-c++ make cmake llvm clang elfutils-libelf-devel rpm-build json-glib-devel python3 libxml2-devel openssl-devel ncurses-devel
```

### Debian 11
```
wget https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb
sudo apt update
sudo apt -y install build-essential gcc g++ make cmake libelf-dev llvm clang libzstd1 git libjson-glib-dev libxml2 libxml2-dev libssl-dev
```

## Build
```
cd
git clone https://github.com/Sysinternals/ProcMon-for-Linux.git
cd ProcMon-for-Linux
mkdir build
cd build
cmake ..
make
```

## Run
```
sudo ./procmon
```

## Make Packages
Packages can be generated with:
```
make deb
```
or
```
make rpm
```

The directories build/deb and build/rpm will be populated with the required
files. If dpkg-deb is available, the build/deb directory will be used to create
a deb package. Similarly if rpmbuild is available, the build/rpm directory will
be used to create an rpm package.
