# Process Monitor for Linux [![Build Status](https://dev.azure.com/sysinternals/Tools/_apis/build/status/Sysinternals.ProcMon-for-Linux?repoName=Sysinternals%2FProcMon-for-Linux&branchName=main)](https://dev.azure.com/sysinternals/Tools/_build/latest?definitionId=342&repoName=Sysinternals%2FProcMon-for-Linux&branchName=main)
Process Monitor (Procmon) is a Linux reimagining of the classic Procmon tool from the Sysinternals suite of tools for Windows.  Procmon provides a convenient and efficient way for Linux developers to trace the syscall activity on the system.

![Procmon in use](procmon.gif "Procmon in use")

# Installation & Usage

## Requirements

* OS: Ubuntu 18.04 lts
* `cmake` >= 3.14 (build-time only)
* `libsqlite3-dev` >= 3.22 (build-time only)

## Install Procmon

Please see installation instructions [here](INSTALL.md).

## Build Procmon
Please see build instructions [here](BUILD.md).

## Usage
```txt
Usage: procmon [OPTIONS]
   OPTIONS
      -h/--help                Prints this help screen
      -p/--pids                Comma separated list of process IDs to monitor
      -e/--events              Comma separated list of system calls to monitor
      -c/--collect [FILEPATH]  Option to start Procmon in a headless mode
      -f/--file FILEPATH       Open a Procmon trace file
      -l/--log FILEPATH        Log debug traces to file
```

### Examples

The following traces all processes and syscalls on the system:

```sh
sudo procmon
```

The following traces processes with process id 10 and 20:

```sh
sudo procmon -p 10,20
```

The following traces process 20 only syscalls read, write and open at:

```sh
sudo procmon -p 20 -e read,write,openat
```

The following traces process 35 and opens Procmon in headless mode to output all captured events to file `procmon.db`:

```sh
sudo procmon -p 35 -c procmon.db
```

The following opens a Procmon `tracefile`, `procmon.db`, within the Procmon TUI:

```sh
sudo procmon -f procmon.db
```

# Feedback

* Ask a question on Stack Overflow (tag with ProcmonForLinux)
* Request a new feature on GitHub
* Vote for popular feature requests
* File a bug in GitHub Issues

# Contributing

If you are interested in fixing issues and contributing directly to the code base, please see the [document How to Contribute](CONTRIBUTING.md), which covers the following:

* How to build and run from the source
* The development workflow, including debugging and running tests
* Coding Guidelines
* Submitting pull requests

Please see also our [Code of Conduct](CODE_OF_CONDUCT.md).

# License

Copyright (c) Microsoft Corporation. All rights reserved.

Licensed under the MIT License.
