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

#include "ne7ssh_connection.h"
#include "ne7ssh_kex.h"
#include "ne7ssh.h"

using namespace Botan;

ne7ssh_connection::ne7ssh_connection()
    : _session(new ne7ssh_session()),
    _sock((SOCKET)-1),
    _thisChannel(0),
    _crypto(new ne7ssh_crypt(_session)),
    _transport(new ne7ssh_transport(_session)),
    _channel(new ne7ssh_channel(_session)),
    _connected(false),
    _cmdRunning(false),
    _cmdClosed(false)
{
    _session->_transport = _transport;
    _session->_crypto = _crypto;
}

ne7ssh_connection::~ne7ssh_connection()
{
}

int ne7ssh_connection::connectWithPassword(uint32 channelID, const char* host, short port, const char* username, const char* password, bool shell, int timeout)
{
    _sock = _transport->establish(host, port, timeout);
    if (_sock == -1)
    {
        return -1;
    }

    if (!checkRemoteVersion())
    {
        return -1;
    }
    if (!sendLocalVersion())
    {
        return -1;
    }

    ne7ssh_kex kex(_session);
    if (!kex.sendInit())
    {
        return -1;
    }
    if (!kex.handleInit())
    {
        return -1;
    }

    if (!kex.sendKexDHInit())
    {
        return -1;
    }
    if (!kex.handleKexDHReply())
    {
        return -1;
    }

    if (!kex.sendKexNewKeys())
    {
        return -1;
    }

    if (!requestService("ssh-userauth"))
    {
        return -1;
    }
    if (!authWithPassword(username, password))
    {
        return -1;
    }

    _thisChannel = _channel->open(channelID);
    if (!_thisChannel)
    {
        return -1;
    }

    if (shell)
    {
        _channel->getShell();
    }

    _connected = true;
    this->_session->setSshChannel(_thisChannel);
    return _thisChannel;
}

int ne7ssh_connection::connectWithKey(uint32 channelID, const char* host, short port, const char* username, const char* privKeyFileName, bool shell, int timeout)
{
    _sock = _transport->establish(host, port, timeout);
    if (_sock == -1)
    {
        return -1;
    }

    if (!checkRemoteVersion())
    {
        return -1;
    }
    if (!sendLocalVersion())
    {
        return -1;
    }

    ne7ssh_kex kex(_session);
    if (!kex.sendInit())
    {
        return -1;
    }
    if (!kex.handleInit())
    {
        return -1;
    }

    if (!kex.sendKexDHInit())
    {
        return -1;
    }
    if (!kex.handleKexDHReply())
    {
        return -1;
    }

    if (!kex.sendKexNewKeys())
    {
        return -1;
    }

    if (!requestService("ssh-userauth"))
    {
        return -1;
    }
    if (!authWithKey(username, privKeyFileName))
    {
        return -1;
    }

    _thisChannel = _channel->open(channelID);
    if (!_thisChannel)
    {
        return -1;
    }

    if (shell)
    {
        _channel->getShell();
    }

    _connected = true;

    this->_session->setSshChannel(_thisChannel);
    return _thisChannel;
}

bool ne7ssh_connection::requestService(const char* service)
{
    ne7ssh_string packet;
    packet.addChar(SSH2_MSG_SERVICE_REQUEST);
    packet.addString(service);

    if (!_transport->sendPacket(packet.value()))
    {
        return false;
    }
    if (!_transport->waitForPacket(SSH2_MSG_SERVICE_ACCEPT))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Service request failed.");
        return false;
    }
    return true;
}

bool ne7ssh_connection::authWithPassword(const char* username, const char* password)
{
    short cmd;
    ne7ssh_string packet;
    SecureVector<Botan::byte> response;
    SecureVector<Botan::byte> methods;

    packet.addChar(SSH2_MSG_USERAUTH_REQUEST);
    packet.addString(username);
    packet.addString("ssh-connection");
    packet.addString("password");
    packet.addChar('\0');
    packet.addString(password);

    if (!_transport->sendPacket(packet.value()))
    {
        return false;
    }
    cmd = _transport->waitForPacket(0);
    if (cmd == SSH2_MSG_USERAUTH_SUCCESS)
    {
        return true;
    }
    else if (cmd == SSH2_MSG_USERAUTH_BANNER)
    {
        packet.clear();
        packet.addString(password);
        if (!_transport->sendPacket(packet.value()))
        {
            return false;
        }
        cmd = _transport->waitForPacket(0);
        if (cmd == SSH2_MSG_USERAUTH_SUCCESS)
        {
            return true;
        }
    }

    if (cmd == SSH2_MSG_USERAUTH_FAILURE)
    {
        _transport->getPacket(response);
        ne7ssh_string message(response, 1);
        message.getString(methods);
        message.getByte();
        ne7ssh::errors()->push(-1, "Authentication failed. Supported authentication methods: %B", &methods);
        return false;
    }
    else
    {
        return false;
    }
}

bool ne7ssh_connection::authWithKey(const char* username, const char* privKeyFileName)
{
    ne7ssh_keys keyPair;
    ne7ssh_string packet, packetBegin, packetEnd;
    SecureVector<Botan::byte> pubKeyBlob, sigBlob;
    if (!keyPair.getKeyPairFromFile(privKeyFileName))
    {
        return false;
    }
    short cmd;
    SecureVector<Botan::byte> response;
    SecureVector<Botan::byte> methods;

    packetBegin.addChar(SSH2_MSG_USERAUTH_REQUEST);
    packetBegin.addString(username);
    packetBegin.addString("ssh-connection");
    packetBegin.addString("publickey");

    switch (keyPair.getKeyAlgo())
    {
        case ne7ssh_keys::DSA:
            packetEnd.addString("ssh-dss");
            break;

        case ne7ssh_keys::RSA:
            packetEnd.addString("ssh-rsa");
            break;

        default:
            ne7ssh::errors()->push(_session->getSshChannel(), "The key algorithm: %i is not supported.", keyPair.getKeyAlgo());
            return false;
    }
    pubKeyBlob = keyPair.getPublicKeyBlob();
    if (!pubKeyBlob.size())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Invallid public key.");
        return false;
    }
    packetEnd.addVectorField(pubKeyBlob);

    packet.addVector(packetBegin.value());
    packet.addChar(0x0);
    packet.addVector(packetEnd.value());

    if (!_transport->sendPacket(packet.value()))
    {
        return false;
    }

    cmd = _transport->waitForPacket(0);
    if (cmd == SSH2_MSG_USERAUTH_FAILURE)
    {
        _transport->getPacket(response);
        ne7ssh_string message(response, 1);
        message.getString(methods);
        message.getByte();
        ne7ssh::errors()->push(-1, "Authentication failed. Supported methods are: %B", &methods);
        return false;
    }
    else if (cmd != SSH2_MSG_USERAUTH_PK_OK)
    {
        return false;
    }

    packet.clear();
    packet.addVector(packetBegin.value());
    packet.addChar(0x1);
    packet.addVector(packetEnd.value());

    sigBlob = keyPair.generateSignature(_session->getSessionID(), packet.value());
    if (!sigBlob.size())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Failure while generating the signature.");
        return false;
    }

    packet.addVectorField(sigBlob);
    if (!_transport->sendPacket(packet.value()))
    {
        return false;
    }

    cmd = _transport->waitForPacket(0);
    if (cmd == SSH2_MSG_USERAUTH_SUCCESS)
    {
        return true;
    }
    else if (cmd == SSH2_MSG_USERAUTH_FAILURE)
    {
        _transport->getPacket(response);
        ne7ssh_string message(response, 1);
        message.getString(methods);
        message.getByte();
        ne7ssh::errors()->push(-1, "Authentication failed. Supported methods are: %B", &methods);
        return false;
    }
    else
    {
        return false;
    }
}

bool ne7ssh_connection::checkRemoteVersion()
{
    SecureVector<Botan::byte> remoteVer, tmpVar;
    Botan::byte* _pos;
    if (!_transport->receive(remoteVer))
    {
        return false;
    }

    if (remoteVer.size() < 4 || \
        (memcmp(remoteVer.begin(), "SSH-1.99", 8) && memcmp(remoteVer.begin(), "SSH-2", 5)))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Remote SSH version is not supported. Remote version: %B.", &remoteVer);
        return false;
    }
    else
    {
        _pos = remoteVer.end() - 1;
        while (*_pos == '\r' || *_pos == '\n')
        {
            _pos--;
        }
        tmpVar = SecureVector<Botan::byte>(remoteVer.begin(), _pos - remoteVer.begin() + 1);
        _session->setRemoteVersion(tmpVar);
        return true;
    }
}

bool ne7ssh_connection::sendLocalVersion()
{
    SecureVector<Botan::byte> localVer((const Botan::byte*)ne7ssh::SSH_VERSION, (uint32_t) strlen(ne7ssh::SSH_VERSION));
    _session->setLocalVersion(localVer);
    localVer += SecureVector<Botan::byte>((const Botan::byte*)"\r\n", 2);

    if (!_transport->send(localVer))
    {
        return false;
    }
    else
    {
        return true;
    }
}

void ne7ssh_connection::handleData()
{
    _channel->receive();
}

void ne7ssh_connection::sendData(const char* data)
{
    SecureVector<Botan::byte> cmd((const Botan::byte*) data, (uint32_t)strlen(data));
    _channel->write(cmd);
}

bool ne7ssh_connection::sendCmd(const char* cmd)
{
    _cmdRunning = true;
    return _channel->execCmd(cmd);
}

std::shared_ptr<Ne7sshSftp> ne7ssh_connection::startSftp()
{
    if (_channel->isRemoteShell())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Remote shell is running. SFTP subsystem cannot be started.");
        return 0;
    }
    _sftp.reset(new Ne7sshSftp(_session, _channel));

    if (_sftp->init())
    {
        return _sftp;
    }
    else
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Failure to launch remote sftp subsystem.");
    }

    return 0;
}

bool ne7ssh_connection::sendClose()
{
    bool status;
    if (_channel->isOpen() && !isSftpActive())
    {
        return (_channel->sendClose());
    }
    else if (getCmdComplete())
    {
        _cmdClosed = true;
    }
    if (isSftpActive())
    {
        _sftp.reset();
        status = _channel->sendClose();
        return status;
    }
    else
    {
        return false;
    }
}

bool ne7ssh_connection::isSftpActive()
{
    if (_sftp)
    {
        return true;
    }
    else
    {
        return false;
    }
}

