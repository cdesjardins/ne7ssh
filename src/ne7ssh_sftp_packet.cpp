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

#include "ne7ssh_sftp_packet.h"
#include "ne7ssh.h"

using namespace Botan;

Ne7sshSftpPacket::Ne7sshSftpPacket () : ne7ssh_string(), _channel(-1)
{
}

Ne7sshSftpPacket::Ne7sshSftpPacket (int channel) : ne7ssh_string(), _channel(_channel)
{
}

Ne7sshSftpPacket::Ne7sshSftpPacket (Botan::SecureVector<Botan::byte>& var, uint32 position) : ne7ssh_string(var, position), _channel(-1)
{
}

Ne7sshSftpPacket::~Ne7sshSftpPacket()
{
}

Botan::SecureVector<Botan::byte> &Ne7sshSftpPacket::value()
{
    ne7ssh_string tmpVar;

    if (this->_channel < 0)
    {
        _buffer.clear();
        return _buffer;
    }

    tmpVar.addChar(SSH2_MSG_CHANNEL_DATA);
    tmpVar.addInt(_channel);
    tmpVar.addInt(sizeof(uint32) + _buffer.size());
    tmpVar.addVectorField(_buffer);

    _buffer.swap(tmpVar.value());
    return _buffer;
}

Botan::SecureVector<Botan::byte> Ne7sshSftpPacket::valueFragment(uint32 len)
{
    ne7ssh_string tmpVar;

    if (this->_channel < 0)
    {
        _buffer.clear();
        return Botan::SecureVector<Botan::byte>();
    }

    tmpVar.addChar(SSH2_MSG_CHANNEL_DATA);
    tmpVar.addInt(_channel);
    if (len)
    {
        tmpVar.addInt(sizeof(uint32) + _buffer.size());
        tmpVar.addInt(len);
        tmpVar.addVector(_buffer);
    }
    else
    {
        tmpVar.addVectorField(_buffer);
    }

    return Botan::SecureVector<Botan::byte> (tmpVar.value());
}

void Ne7sshSftpPacket::addInt64(const uint64 var)
{
    uint8 converter[8];

    converter[0] = (uint8) (var >> 56);
    converter[1] = (uint8) (var >> 48);
    converter[2] = (uint8) (var >> 40);
    converter[3] = (uint8) (var >> 32);
    converter[4] = (uint8) (var >> 24);
    converter[5] = (uint8) (var >> 16);
    converter[6] = (uint8) (var >> 8);
    converter[7] = (uint8) var;

    addBytes(converter, 8);
}

uint64 Ne7sshSftpPacket::getInt64()
{
    SecureVector<Botan::byte> tmpVar(_buffer);
    uint64 result;
    uint8 converter[8];
    memcpy(converter, tmpVar.begin(), 8);

    result = (uint64)converter[0] << 56;
    result |= (uint64)converter[1] << 48;
    result |= (uint64)converter[2] << 40;
    result |= (uint64)converter[3] << 32;
    result |= (uint64)converter[4] << 24;
    result |= (uint64)converter[5] << 16;
    result |= (uint64)converter[6] << 8;
    result |= (uint64)converter[7];

    _buffer = SecureVector<Botan::byte>(tmpVar.begin() + sizeof(uint64), tmpVar.size() - sizeof(uint64));
    return result;
}

bool Ne7sshSftpPacket::isChannelSet()
{
    if (this->_channel == -1)
    {
        return false;
    }
    else
    {
        return true;
    }
}

