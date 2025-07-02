/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#pragma once

#include <experimental/filesystem>
#include <fstream>
#include <map>
#include <regex>
#include <string>
#include <vector>
#include <iostream>
#include <cstring>

#include "kern/procmonEBPF_common.h"
#include "syscalls.h"

    class Utils
    {
    public:
        static std::map<std::string, ProcmonArgTag> ArgTypeStringToArgTag;
        static std::vector<std::string> Linux64PointerSycalls;

        static int GetSyscallNumberForName(const std::string& name)
        {
            for(const auto& syscall : syscalls)
            {
                if (syscall.name == name)
                {
                    return syscall.number;
                }
            }

            return -1;
        }

        static ProcmonArgTag GetArgTagForArg(const std::string &argumentName, const std::string &argumentType)
        {
            auto maybeTag = ArgTypeStringToArgTag.find(argumentType);
            if (maybeTag != ArgTypeStringToArgTag.end())
                return maybeTag->second;
            else if (argumentName == "fd")
                return ProcmonArgTag::FD;
            else if (argumentType.find("*") != std::string::npos)
            {
                return ProcmonArgTag::PTR;
            }
            else
                return ProcmonArgTag::NOTKNOWN;
        }

        static std::vector<struct SyscallSchema> CollectSyscallSchema()
        {
            std::vector<SyscallSchema> schemas;
            schemas.reserve(350);

            std::regex filenameRegex("(.*)/sys_enter_([a-z0-9_]+)");
            // The line that contains this substring is up to where we skip to.
            std::regex syscall_nrRegex("__syscall_nr");
            // Regex to parse argument info.
            std::regex argFieldTypeName("(field:)([a-zA-Z0-9_\\s\\*]+)(;)");
            // Regex to parse arg and name
            std::regex argTypeAndName("([a-z\\* _]+)+ ([a-z_]+)$");

            for(const auto& syscall : syscalls)
            {
                SyscallSchema schema;
                std::smatch match;

                if (syscall.entrypoint.compare(0, 4, "sys_") == 0)
                {
                    std::string sysDir = "sys_enter_" + syscall.entrypoint.substr(4);
                    int syscallNameLen = sizeof(schema.syscallName) / sizeof(schema.syscallName[0]);
                    strncpy(schema.syscallName, syscall.name.c_str(), syscallNameLen -1);
                    schema.syscallName[syscallNameLen - 1] = '\0';
                    
                    std::string filePath = "/sys/kernel/debug/tracing/events/syscalls/" + sysDir + "/format";
                    std::ifstream file(filePath);

                     // Skip all that we don't care about.
                    std::string line;
                    while (std::getline(file, line))
                        if (std::regex_search(line, match, syscall_nrRegex))
                            break;

                    // Start interpreting lines since everything but the last line is what we are about.
                    int argCount = 0;
                    while (std::getline(file, line))
                    {
                        if (std::regex_search(line, match, argFieldTypeName))
                        {
                            int i1 = line.find(":");
                            int i2 = line.find(";");
                            std::string res = line.substr(i1+1, i2-i1-1);
                            int lastPos = res.find_last_of(" ");

                            std::string argName = res.substr(lastPos+1, res.length()-lastPos-1);
                            std::string argType = res.substr(0, lastPos);
                            int argLen = sizeof(schema.argNames[argCount]) / sizeof(schema.argNames[argCount][0]);
                            strncpy(schema.argNames[argCount], argName.c_str(), argLen -1);
                            schema.argNames[argCount][argLen -1] = '\0';
                            schema.types[argCount] = GetArgTagForArg(argName, argType);
                            argCount++;
                        }
                    }
                    // Make sure to record how many arguments we actually have for this syscall.
                    schema.usedArgCount = argCount;
                    schemas.push_back(schema);
                }
            }

            return schemas;
        }
    private:
        Utils();
    };
