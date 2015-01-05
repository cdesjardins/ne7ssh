/***************************************************************************
 *   Copyright (C) 2005-2007 by NetSieben Technologies INC                 *
 *   Author: Andrew Useckas                                                *
 *   Email: andrew@netsieben.com                                           *
 *                                                                         *
 *   This program may be distributed under the terms of the Q Public       *
 *   License as defined by Trolltech AS of Norway and appearing in the     *
 *   file LICENSE.QPL included in the packaging of this file.              *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                  *
 ***************************************************************************/

#include <botan/secmem.h>
#include "ne7ssh_error.h"
#include <string.h>
#include <cstdio>
#include "stdarg.h"
#include "ne7ssh.h"

using namespace Botan;
std::recursive_mutex Ne7sshError::_mutex;

Ne7sshError::Ne7sshError()
{
}

Ne7sshError::~Ne7sshError()
{
}

bool Ne7sshError::push(int32 channel, const char* format, ...)
{
    va_list args;
    char* s;
    std::string errStr;
    uint32 len = 0, msgLen = 0;
    bool isArg = false;
    bool isUnsigned = false;
    char converter[21];
    SecureVector<Botan::byte>* secVec;
    int32 i;

    if (channel < -1 || !format)
    {
        return false;
    }

    converter[0] = 0x00;

    va_start(args, format);

    do
    {
        if (*format == '%' || isArg)
        {
            switch (*format)
            {
                case '%':
                    isArg = true;
                    break;

                case 'u':
                    isUnsigned = true;
                    break;

                case 's':
                    s = va_arg(args, char*);
                    msgLen = strlen(s);
                    if (msgLen > MAX_ERROR_LEN)
                    {
                        msgLen = MAX_ERROR_LEN;
                    }
                    errStr.append(s, msgLen);
                    if (isUnsigned)
                    {
                        len += msgLen - 3;
                    }
                    else
                    {
                        len += msgLen - 2;
                    }
                    isUnsigned = false;
                    isArg = false;
                    break;

                case 'B':
                    secVec = va_arg(args, SecureVector<Botan::byte>*);
                    msgLen = secVec->size();
                    if (msgLen > MAX_ERROR_LEN)
                    {
                        msgLen = MAX_ERROR_LEN;
                    }
                    errStr.append((char*)secVec->begin(), msgLen);
                    if (isUnsigned)
                    {
                        len += msgLen - 3;
                    }
                    else
                    {
                        len += msgLen - 2;
                    }
                    isUnsigned = false;
                    isArg = false;
                    break;

                case 'l':
                case 'd':
                case 'i':
                    i = va_arg(args, int32);
                    if (isUnsigned)
                    {
                        sprintf(converter, "%u", i);
                    }
                    else
                    {
                        sprintf(converter, "%d", i);
                    }
                    msgLen = strlen(converter);
                    errStr.append(converter, msgLen);
                    if (isUnsigned)
                    {
                        len += msgLen - 3;
                    }
                    else
                    {
                        len += msgLen - 2;
                    }
                    isUnsigned = false;
                    isArg = false;
                    break;

                case 'x':
                    i = va_arg(args, int32);
                    sprintf(converter, "%x", i);
                    msgLen = strlen(converter);
                    errStr.append(converter, msgLen);
                    if (isUnsigned)
                    {
                        len += msgLen - 3;
                    }
                    else
                    {
                        len += msgLen - 2;
                    }
                    isUnsigned = false;
                    isArg = false;
                    break;
            }
        }
        else
        {
            errStr.push_back(*format);
        }
    } while (*format++);

    va_end(args);

    std::unique_lock<std::recursive_mutex> lock(_mutex);

    _errorBuffers[channel].push(errStr);
    return true;
}

const std::string Ne7sshError::pop()
{
    return pop(-1);
}

const std::string Ne7sshError::pop(int32 channel)
{
    std::string result;
    std::unique_lock<std::recursive_mutex> lock(_mutex);
    std::map<int32, std::queue<std::string> >::iterator bufs = _errorBuffers.find(channel);
    if (bufs != _errorBuffers.end())
    {
        std::queue<std::string> errQ = bufs->second;
        if (errQ.empty() == false)
        {
            result = errQ.front();
            bufs->second.pop();
        }
    }

    return result;
}

void Ne7sshError::deleteCoreMsgs()
{
    deleteChannel(-1);
}

void Ne7sshError::deleteChannel(int32 channel)
{
    std::unique_lock<std::recursive_mutex> lock(_mutex);
    std::map<int32, std::queue<std::string> >::iterator bufs = _errorBuffers.find(channel);
    if (bufs != _errorBuffers.end())
    {
        _errorBuffers.erase(bufs);
    }
}

