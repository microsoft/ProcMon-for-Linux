/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef STACK_TRACE_H
#define STACK_TRACE_H

#include <string>
#include <vector>
#include <sstream>
#include <stdint.h>

struct StackTrace
{
    std::vector<uint64_t> kernelIPs;
    std::vector<std::string> kernelSymbols;
    std::vector<uint64_t> userIPs;
    std::vector<std::string> userSymbols;

    StackTrace() {}

    std::string Serialize()
    {
        std::string ret;

        if(userIPs.size() == 0)
        {
            return "";
        }

        ret += std::to_string(userIPs[0]);

        for(int i = 1; i < userIPs.size(); i++)
        {
            ret += ";" + std::to_string(userIPs[i]);
        }
        return ret;
    }

    void Inflate(std::string blob)
    {
        std::string token;
        std::stringstream stream(blob);

        while(std::getline(stream, token, ';'))
        {
            userIPs.push_back(std::stoull(token));
        }
    }

};

#endif // STACK_TRACE_H
