/***************************************************************************
 *   Copyright (C) 2005-2007 by NetSieben Technologies INC                 *
 *   Author: Andrew Useckas                                                *
 *   Email: andrew@netsieben.com                                           *
 *                                                                         *
 *   Windows Port and bugfixes: Keef Aragon <keef@netsieben.com>           *
 *                                                                         *
 *   This program may be distributed under the terms of the Q Public       *
 *   License as defined by Trolltech AS of Norway and appearing in the     *
 *   file LICENSE.QPL included in the packaging of this file.              *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                  *
 ***************************************************************************/

#include "ne7ssh_string.h"
#include "ne7ssh.h"
#include <cstdio>
#if !defined(WIN32) && !defined(__MINGW32__)
#   include <arpa/inet.h>
#else
#   include <Winsock2.h>
#endif

using namespace Botan;

ne7ssh_string::ne7ssh_string() : _currentPart(0)
{
}

ne7ssh_string::ne7ssh_string(Botan::SecureVector<Botan::byte>& var, uint32 position)
    : _currentPart(0)
{
    _buffer = SecureVector<Botan::byte>((var.begin() + position), (var.size() - position));
}

ne7ssh_string::ne7ssh_string(const char* var, uint32 position)
    : _currentPart(0)
{
    char null_char = 0x0;
    _buffer = SecureVector<Botan::byte>((Botan::byte*)(var + position), (u32bit) (strlen(var) - position));
    _buffer += SecureVector<Botan::byte>((Botan::byte*) &null_char, 1);
}

ne7ssh_string::~ne7ssh_string()
{
}

void ne7ssh_string::addString(const char* str)
{
    Botan::byte* value = (Botan::byte*) str;
    size_t len = strlen(str);
    uint32 nLen = htonl((long) len);

    _buffer += SecureVector<Botan::byte>((Botan::byte*)&nLen, sizeof(uint32));
    _buffer += SecureVector<Botan::byte>(value, (u32bit)len);
}

bool ne7ssh_string::addFile(const char* filename)
{
    FILE* FI = fopen(filename, "rb");
    size_t size;

    if (!FI)
    {
        ne7ssh::errors()->push(-1, "Could not open key file: %s.", filename);
        return false;
    }

    fseek(FI, 0L, SEEK_END);
    size = ftell(FI);
    rewind(FI);

    std::unique_ptr<Botan::byte> data(new Botan::byte[size]);
    fread(data.get(), size, 1, FI);
    fclose(FI);
    _buffer += SecureVector<Botan::byte>(data.get(), (u32bit)size);
    return true;
}

void ne7ssh_string::addBigInt(const Botan::BigInt& bn)
{
    SecureVector<Botan::byte> converted;
    bn2vector(converted, bn);
    uint32 nLen = htonl(converted.size());

    _buffer += SecureVector<Botan::byte>((Botan::byte*)&nLen, sizeof(uint32));
    _buffer += SecureVector<Botan::byte>(converted);
}

void ne7ssh_string::addVectorField(const Botan::SecureVector<Botan::byte> &vector)
{
    uint32 nLen = htonl(vector.size());

    _buffer += SecureVector<Botan::byte>((Botan::byte*)&nLen, sizeof(uint32));
    _buffer += vector;
}

void ne7ssh_string::addBytes(const Botan::byte* buff, uint32 len)
{
    _buffer += SecureVector<Botan::byte>(buff, len);
}

void ne7ssh_string::addVector(Botan::SecureVector<Botan::byte> &secvec)
{
    _buffer += SecureVector<Botan::byte>(secvec.begin(), secvec.size());
}

void ne7ssh_string::addChar(const char ch)
{
    _buffer += SecureVector<Botan::byte>((Botan::byte*)&ch, 1);
}

void ne7ssh_string::addInt(const uint32 var)
{
    uint32 nVar = htonl(var);

    _buffer += SecureVector<Botan::byte>((Botan::byte*)&nVar, sizeof(uint32));
}

bool ne7ssh_string::getString(Botan::SecureVector<Botan::byte>& result)
{
    SecureVector<Botan::byte> tmpVar(_buffer);
    uint32 len;

    len = ntohl(*((uint32*)tmpVar.begin()));
    if (len > tmpVar.size())
    {
        return false;
    }

    result = SecureVector<Botan::byte>(tmpVar.begin() + sizeof(uint32), len);
    _buffer = SecureVector<Botan::byte>(tmpVar.begin() + sizeof(uint32) + len, tmpVar.size() - sizeof(uint32) - len);
    return true;
}

bool ne7ssh_string::getBigInt(Botan::BigInt& result)
{
    SecureVector<Botan::byte> tmpVar(_buffer);
    uint32 len;

    len = ntohl(*((uint32*)tmpVar.begin()));
    if (len > tmpVar.size())
    {
        return false;
    }

    BigInt tmpBI(tmpVar.begin() + sizeof(uint32), len);
    result.swap(tmpBI);
    _buffer = SecureVector<Botan::byte>(tmpVar.begin() + sizeof(uint32) + len, tmpVar.size() - sizeof(uint32) - len);
    return true;
}

uint32 ne7ssh_string::getInt()
{
    SecureVector<Botan::byte> tmpVar(_buffer);
    uint32 result;

    result = ntohl(*((uint32*)tmpVar.begin()));
    _buffer = SecureVector<Botan::byte>(tmpVar.begin() + sizeof(uint32), tmpVar.size() - sizeof(uint32));
    return result;
}

Botan::byte ne7ssh_string::getByte()
{
    SecureVector<Botan::byte> tmpVar(_buffer);
    Botan::byte result;

    result = *(tmpVar.begin());
    _buffer = SecureVector<Botan::byte>(tmpVar.begin() + 1, tmpVar.size() - 1);
    return result;
}

void ne7ssh_string::split(const char token)
{
    Botan::byte* buffer = _buffer.begin();
    uint32 len = _buffer.size();
    uint32 i;

    if (_positions.size() != 0)
    {
        return;
    }
    _positions.push_back(buffer);

    for (i = 0; i < len; i++)
    {
        if (buffer[i] == token)
        {
            buffer[i] = '\0';

            _positions.push_back(buffer + i + 1);
        }
    }
}

char* ne7ssh_string::nextPart()
{
    char* result;
    if (_currentPart >= _positions.size() || _positions.size() == 0)
    {
        return NULL;
    }

    result = (char*) _positions[_currentPart];
    _currentPart++;

    return result;
}

void ne7ssh_string::chop(uint32 nBytes)
{
    SecureVector<Botan::byte> tmpVar(_buffer);
    _buffer = SecureVector<Botan::byte>(tmpVar.begin(), tmpVar.size() - nBytes);
}

void ne7ssh_string::bn2vector(Botan::SecureVector<Botan::byte>& result, const Botan::BigInt& bi)
{
    int high;
    Botan::byte zero = '\0';

    SecureVector<Botan::byte> strVector = BigInt::encode(bi);

    high = (*(strVector.begin()) & 0x80) ? 1 : 0;

    if (high)
    {
        result = SecureVector<Botan::byte>(&zero, 1);
    }
    else
    {
        result.clear();
    }
    result += strVector;
}

