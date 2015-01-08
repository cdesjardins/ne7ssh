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

#include "ne7ssh_transport.h"
#include "ne7ssh.h"
#include "ne7ssh_session.h"

#if defined(WIN32) || defined(__MINGW32__)
#   define SOCKET_BUFFER_TYPE char
#   define close closesocket
#   define SOCK_CAST (char*)
class WSockInitializer
{
public:
    WSockInitializer()
    {
        static WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }

    ~WSockInitializer()
    {
        WSACleanup();
    }
}
;
WSockInitializer _wsock32_;
#else
#   define SOCKET_BUFFER_TYPE void
#   define SOCK_CAST (void*)
#   include <sys/socket.h>
#   include <netinet/in.h>
#   include <netdb.h>
#   include <unistd.h>
#   include <fcntl.h>
#endif

using namespace Botan;

ne7ssh_transport::ne7ssh_transport(std::shared_ptr<ne7ssh_session> session)
    : _seq(0),
    _rSeq(0),
    _session(session),
    _sock((SOCKET)-1)
{
}

ne7ssh_transport::~ne7ssh_transport()
{
    if (((long)_sock) > -1)
    {
        close(_sock);
    }
}

SOCKET ne7ssh_transport::establish(const char* host, short port, int timeout)
{
    sockaddr_in remoteAddr;
    hostent* remoteHost;

    remoteHost = gethostbyname(host);
    if (!remoteHost || remoteHost->h_length == 0)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Host: '%s' not found.", host);
        return (SOCKET)-1;
    }
    remoteAddr.sin_family = AF_INET;
    remoteAddr.sin_addr.s_addr = *(long*) remoteHost->h_addr_list[0];
    remoteAddr.sin_port = htons(port);

    _sock = socket(AF_INET, SOCK_STREAM, 0);
    if (_sock < 0)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Failure to bind to socket.");
        return (SOCKET)-1;
    }

    if (timeout < 1)
    {
        if (connect(_sock, (struct sockaddr*) &remoteAddr, sizeof(remoteAddr)))
        {
            ne7ssh::errors()->push(_session->getSshChannel(), "Unable to connect to remote server: '%s'.", host);
            return (SOCKET)-1;
        }

        if (!NoBlock(_sock, true))
        {
            return (SOCKET)-1;
        }
        else
        {
            return _sock;
        }
    }
    else
    {
        if (!NoBlock(_sock, true))
        {
            return (SOCKET)-1;
        }

        if (connect(_sock, (struct sockaddr*) &remoteAddr, sizeof(remoteAddr)) == -1)
        {
            fd_set rfds;
            struct timeval waitTime;

            waitTime.tv_sec = timeout;
            waitTime.tv_usec = 0;

            FD_ZERO(&rfds);
#if defined(WIN32)
#pragma warning(push)
#pragma warning(disable : 4127)
#endif
            FD_SET(_sock, &rfds);
#if defined(WIN32)
#pragma warning(pop)
#endif
            int status;
            status = select(_sock + 1, &rfds, NULL, NULL, &waitTime);

            if (status == 0)
            {
                if (!FD_ISSET(_sock, &rfds))
                {
                    ne7ssh::errors()->push(_session->getSshChannel(), "Couldn't connect to remote server : timeout");
                    return (SOCKET)-1;
                }
            }
            if (status < 0)
            {
                ne7ssh::errors()->push(_session->getSshChannel(), "Couldn't connect to remote server during select");
                return (SOCKET)-1;
            }
        }
        return _sock;
    }
}

bool ne7ssh_transport::NoBlock(SOCKET socket, bool on)
{
#ifndef WIN32
    int options;
    if ((options = fcntl(socket, F_GETFL)) < 0)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Cannot read options of the socket: %i.", (int)socket);
        return false;
    }

    if (on)
    {
        options = (options | O_NONBLOCK);
    }
    else
    {
        options = (options & ~O_NONBLOCK);
    }
    fcntl(socket, F_SETFL, options);
#else
    unsigned long options = on;
    if (ioctlsocket(socket, FIONBIO, &options))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Cannot set asynch I/O on the socket: %i.", (int)socket);
        return false;
    }
#endif
    return true;
}

bool ne7ssh_transport::haveData()
{
    return wait(_sock, 0, 0);
}

bool ne7ssh_transport::wait(SOCKET socket, int rw, int timeout)
{
    int status;
    fd_set rfds, wfds;
    struct timeval waitTime;

    if (timeout > -1)
    {
        waitTime.tv_sec = timeout;
        waitTime.tv_usec = 0;
    }

#if defined(WIN32)
#pragma warning(push)
#pragma warning(disable : 4127)
#endif
    if (!rw)
    {
        FD_ZERO(&rfds);
        FD_SET(socket, &rfds);
    }
    else
    {
        FD_ZERO(&wfds);
        FD_SET(socket, &wfds);
    }
#if defined(WIN32)
#pragma warning(pop)
#endif

    if (!rw)
    {
        if (timeout > -1)
        {
            status = select(socket + 1, &rfds, NULL, NULL, &waitTime);
        }
        else
        {
            status = select(socket + 1, &rfds, NULL, NULL, NULL);
        }
    }
    else
    {
        status = select(socket + 1, NULL, &wfds, NULL, NULL);
    }

    if (status > 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}

bool ne7ssh_transport::send(Botan::SecureVector<Botan::byte>& buffer)
{
    size_t byteCount;
    uint32 sent = 0;

    if (buffer.size() > MAX_PACKET_LEN)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Cannot send. Packet too large for the transport layer.");
        return false;
    }

    while (sent < buffer.size())
    {
        if (wait(_sock, 1))
        {
            byteCount = ::send(_sock, (const SOCKET_BUFFER_TYPE*)(buffer.begin() + sent), buffer.size() - sent, 0);
        }
        else
        {
            return false;
        }
        if (byteCount < 0)
        {
            return false;
        }
        sent += byteCount;
    }

    return true;
}

bool ne7ssh_transport::receive(Botan::SecureVector<Botan::byte>& buffer)
{
    Botan::byte in_buffer[MAX_PACKET_LEN];
    int len = 0;

    if (wait(_sock, 0))
    {
        len = ::recv(_sock, (char*)in_buffer, MAX_PACKET_LEN, 0);
    }

    if (!len)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Received a packet of zero length.");
        return false;
    }

    if (len > MAX_PACKET_LEN)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Received packet exceeds the maximum size");
        return false;
    }

    if (len < 0)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Connection dropped");
        return false;
    }

    buffer += SecureVector<Botan::byte>(in_buffer, len);

    return true;
}

bool ne7ssh_transport::sendPacket(Botan::SecureVector<Botan::byte> &buffer)
{
    std::shared_ptr<ne7ssh_crypt> crypto = _session->_crypto;
    ne7ssh_string out;
    uint32 crypt_block;
    char padLen;
    uint32 packetLen;
    uint32 length;
    SecureVector<Botan::byte> crypted, hmac;

// No Zlib support right now
//  if (crypto->isInited()) crypto->compressData (buffer);
    length = buffer.size();

    crypt_block = crypto->getEncryptBlock();
    if (!crypt_block)
    {
        crypt_block = 8;
    }

    padLen = (char)(3 + crypt_block - ((length + 8) % crypt_block));
    packetLen = 1 + length + padLen;

    out.addInt(packetLen);
    out.addChar(padLen);
    out.addVector(buffer);

    std::unique_ptr<Botan::byte> padBytes(new Botan::byte[padLen]);
    memset(padBytes.get(), 0x00, padLen);
    out.addBytes(padBytes.get(), padLen);
    padBytes.reset();

    if (crypto->isInited())
    {
        if (!crypto->encryptPacket(crypted, hmac, out.value(), _seq))
        {
            ne7ssh::errors()->push(_session->getSshChannel(), "Failure to encrypt the payload.");
            return false;
        }
        crypted += hmac;
        if (!send(crypted))
        {
            return false;
        }
    }
    else if (!send(out.value()))
    {
        return false;
    }
    if (_seq == MAX_SEQUENCE)
    {
        _seq = 0;
    }
    else
    {
        _seq++;
    }
    return true;
}
#include <iostream>

class ne7ssh_packet {
public:
    ne7ssh_packet(SecureVector<Botan::byte> *encryptedPacket)
        : _buffer(encryptedPacket)
    {

    }

    ne7ssh_packet& operator=(SecureVector<Botan::byte> *encryptedPacket)
    {
        _buffer = encryptedPacket;
        return *this;
    }

    int32 packetLength()
    {
        int32 ret = 0;
        if (_buffer->size() > 4)
        {
            ret = ntohl(*((uint32*)_buffer->begin()));
        }
        return ret;
    }

    int32 cryptoLength()
    {
        int32 ret = packetLength();
        if (ret > 0)
        {
            ret += sizeof(uint32);
        }
        return ret;
    }

    Botan::byte getCommand()
    {
        Botan::byte ret = 0;
        if (_buffer->size() > 5)
        {
            ret = *(_buffer->begin() + 5);
        }
        return ret;
    }

private:
    SecureVector<Botan::byte>* _buffer;
};

short ne7ssh_transport::waitForPacket(Botan::byte command, bool bufferOnly)
{
    std::shared_ptr<ne7ssh_crypt> crypto = _session->_crypto;
    Botan::byte cmd;
    SecureVector<Botan::byte> decrypted;
    ne7ssh_packet packet(&_in);
    uint32 cryptoLen = 0;
    int macLen = 0;

    if (bufferOnly == false)
    {
        size_t size = 4;
        if (crypto->isInited() == true)
        {
            size = crypto->getDecryptBlock();
        }
        while (_in.size() < size)
        {
            if (receive(_in) == false)
            {
                return -1;
            }
        }
    }
    if ((crypto->isInited() == true) && (_in.size() >= crypto->getDecryptBlock()))
    {
        crypto->decryptPacket(decrypted, _in, crypto->getDecryptBlock());
        packet = &decrypted;
        macLen = crypto->getMacInLen();
    }
    cryptoLen = packet.cryptoLength();
    if ((bufferOnly == false) || ((crypto->isInited() == true) && (packet.getCommand() > 0) && (packet.getCommand() < 0xff)))
    {
        while ((cryptoLen + macLen) > _in.size())
        {
            if (receive(_in) == false)
            {
                return -1;
            }
        }
    }

    if (crypto->isInited() == true)
    {
        if (cryptoLen > crypto->getDecryptBlock())
        {
            SecureVector<Botan::byte> tmpVar;
            tmpVar = SecureVector<Botan::byte>(_in.begin() + crypto->getDecryptBlock(), (cryptoLen - crypto->getDecryptBlock()));
            crypto->decryptPacket(tmpVar, tmpVar, tmpVar.size());
            decrypted += tmpVar;
        }
        if (crypto->getMacInLen() && (_in.size() > 0) && (_in.size() >= (cryptoLen + crypto->getMacInLen())))
        {
            SecureVector<Botan::byte> ourMac, hMac;
            crypto->computeMac(ourMac, decrypted, _rSeq);
            hMac = SecureVector<Botan::byte>(_in.begin() + cryptoLen, crypto->getMacInLen());
            if (hMac != ourMac)
            {
                ne7ssh::errors()->push(_session->getSshChannel(), "Mismatched HMACs.");
                return -1;
            }
            cryptoLen += crypto->getMacInLen();
        }
    }
    else
    {
        decrypted = _in;
    }
    if (decrypted.empty() == false)
    {
        _rSeq++;
        cmd = packet.getCommand();
        if ((command == cmd) || (command == 0))
        {
            _inBuffer = decrypted;
            if (_in.size() == cryptoLen)
            {
                _in.clear();
            }
            else
            {
                SecureVector<Botan::byte> tmpVar;
                tmpVar.swap(_in);
                _in = SecureVector<Botan::byte>(tmpVar.begin() + cryptoLen, tmpVar.size() - cryptoLen);
            }
            return cmd;
        }
        else
        {
            return 0;
        }
    }

    return command;
}

uint32 ne7ssh_transport::getPacket(Botan::SecureVector<Botan::byte> &result)
{
    std::shared_ptr<ne7ssh_crypt> crypto = _session->_crypto;
    SecureVector<Botan::byte> tmpVector(_inBuffer);
    uint32 len = ntohl(*((uint32*)tmpVector.begin()));
    Botan::byte padLen = *(tmpVector.begin() + 4);
    uint32 macLen = crypto->getMacInLen();

    if (_inBuffer.empty())
    {
        result.clear();
        return 0;
    }

    if (crypto->isInited())
    {
        len += macLen;
        if (len > tmpVector.size())
        {
            len -= macLen;
        }
    }

    tmpVector += SecureVector<Botan::byte>((uint8*)"\0", 1);
    result = SecureVector<Botan::byte>(tmpVector.begin() + 5, len);
    crypto->decompressData(result);

    _inBuffer.clear();
    return padLen;
}

