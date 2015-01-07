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
#include "ne7ssh_channel.h"
#include "ne7ssh_session.h"
#include "ne7ssh_impl.h"
#include "ne7ssh.h"

using namespace Botan;

//uint32 ne7ssh_channel::channelCount = 0;

ne7ssh_channel::ne7ssh_channel(std::shared_ptr<ne7ssh_session> session)
    : _eof(false),
    _closed(false),
    _cmdComplete(false),
    _shellSpawned(false),
    _session(session),
    _windowRecv(0),
    _windowSend(0),
    _channelOpened(false)
{
}

ne7ssh_channel::~ne7ssh_channel()
{
}

uint32 ne7ssh_channel::open(uint32 channelID)
{
    ne7ssh_string packet;
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;

    packet.addChar(SSH2_MSG_CHANNEL_OPEN);
    packet.addString("session");
    packet.addInt(channelID);
//  ne7ssh_channel::channelCount++;
    _windowSend = 0;
    _windowRecv = MAX_PACKET_LEN - 2400;
    packet.addInt(_windowRecv);
    packet.addInt(MAX_PACKET_LEN);

    if (!transport->sendPacket(packet.value()))
    {
        return 0;
    }
    if (!transport->waitForPacket(SSH2_MSG_CHANNEL_OPEN_CONFIRMATION))
    {
        ne7ssh::errors()->push(-1, "New channel: %i could not be open.", channelID);
        return 0;
    }
    if (handleChannelConfirm())
    {
        _channelOpened = true;
        return channelID;
//    return (ne7ssh_channel::channelCount - 1);
    }
    else
    {
        return 0;
    }
}

bool ne7ssh_channel::handleChannelConfirm()
{
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    SecureVector<Botan::byte> packet;
    transport->getPacket(packet);
    ne7ssh_string channelConfirm(packet, 1);
    uint32 field;

    // Receive Channel
    channelConfirm.getInt();
    // Send Channel
    field = channelConfirm.getInt();
    _session->setSendChannel(field);

    // Window Size
    field = channelConfirm.getInt();
    _windowSend = field;

    // Max Packet
    field = channelConfirm.getInt();
    _session->setMaxPacket(field);
    return true;
}

bool ne7ssh_channel::adjustWindow(Botan::SecureVector<Botan::byte>& packet)
{
    ne7ssh_string adjustWindow(packet, 0);
    ne7ssh_string newPacket;
    uint32 field;

    // channel number
    adjustWindow.getInt();

    // add bytes to the window
    field = adjustWindow.getInt();
    _windowSend += field;
    return true;
}

bool ne7ssh_channel::handleEof(Botan::SecureVector<Botan::byte>& packet)
{
    UNREF_PARAM(packet);
    this->_cmdComplete = true;
    _windowRecv = 0;
    _eof = true;
    if (!_closed)
    {
        sendClose();
    }
    _closed = true;
    _channelOpened = false;
    ne7ssh::errors()->push(_session->getSshChannel(), "Remote side responded with EOF.");
    return false;
}

void ne7ssh_channel::handleClose(Botan::SecureVector<Botan::byte>& newPacket)
{
    UNREF_PARAM(newPacket);
    if (!_closed)
    {
        sendClose();
    }
    _windowRecv = 0;
    _closed = true;
    _channelOpened = false;
}

bool ne7ssh_channel::handleDisconnect(Botan::SecureVector<Botan::byte>& packet)
{
    ne7ssh_string message(packet, 0);
//  uint32 reasonCode = message.getInt ();
    SecureVector<Botan::byte> description;

    message.getString(description);
    _windowSend = _windowRecv = 0;
    _closed = true;
    _channelOpened = false;

    ne7ssh::errors()->push(_session->getSshChannel(), "Remote Site disconnected with Error: %B.", &description);
    return false;
}

bool ne7ssh_channel::sendClose()
{
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    ne7ssh_string packet;

    if (_closed)
    {
        return false;
    }
    packet.addChar(SSH2_MSG_CHANNEL_CLOSE);
    packet.addInt(_session->getSendChannel());

    if (!transport->sendPacket(packet.value()))
    {
        return false;
    }
    _windowSend = 0;
    _windowRecv = 0;
    _closed = true;
    return true;
}

bool ne7ssh_channel::sendEof()
{
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    ne7ssh_string packet;

    if (_closed)
    {
        return false;
    }
    packet.addChar(SSH2_MSG_CHANNEL_EOF);
    packet.addInt(_session->getSendChannel());

    if (!transport->sendPacket(packet.value()))
    {
        return false;
    }
    _windowSend = 0;
    _windowRecv = 0;
    _closed = true;
    return true;
}

void ne7ssh_channel::sendAdjustWindow()
{
    uint32 len = _session->getMaxPacket() - _windowRecv - 2400;
    ne7ssh_string packet;
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;

    packet.addChar(SSH2_MSG_CHANNEL_WINDOW_ADJUST);
    packet.addInt(_session->getSendChannel());
    packet.addInt(len);
    _windowRecv = len;

    transport->sendPacket(packet.value());
}

bool ne7ssh_channel::handleData(Botan::SecureVector<Botan::byte>& packet)
{
    ne7ssh_string handleData(packet, 0);
    SecureVector<Botan::byte> data;

    handleData.getInt();

    if (!handleData.getString(data))
    {
        return false;
    }
    if (!data.size())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Abnormal. End of stream detected.");
    }
    if (_inBuffer.length())
    {
        _inBuffer.chop(1);
    }
    _inBuffer.addVector(data);
    if (_inBuffer.length())
    {
        _inBuffer.addChar(0x00);
    }
    _windowRecv -= data.size();
    if (_windowRecv == 0)
    {
        sendAdjustWindow();
    }
    return true;
}

bool ne7ssh_channel::handleExtendedData(Botan::SecureVector<Botan::byte>& packet)
{
    ne7ssh_string handleData(packet, 0);
    uint32 dataType;
    SecureVector<Botan::byte> data;

    handleData.getInt();
    dataType = handleData.getInt();
    if (dataType != 1)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Unable to handle received request.");
        return false;
    }

    if (handleData.getString(data))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Remote side returned the following error: %B", &data);
    }
    else
    {
        return false;
    }

    _windowRecv -= data.size();
    if (_windowRecv == 0)
    {
        sendAdjustWindow();
    }
    return true;
}

void ne7ssh_channel::handleRequest(Botan::SecureVector<Botan::byte>& packet)
{
    ne7ssh_string handleRequest(packet, 0);
    SecureVector<Botan::byte> field;
    uint32 signal;

    handleRequest.getInt();
    handleRequest.getString(field);
    if (!memcmp((char*)field.begin(), "exit-signal", 11))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "exit-signal ignored.");
    }
    else if (!memcmp((char*)field.begin(), "exit-status", 11))
    {
        handleRequest.getByte();
        signal = handleRequest.getInt();
        ne7ssh::errors()->push(_session->getSshChannel(), "Remote side exited with status: %i.", signal);
    }

//  handleRequest.getByte();
//  handleRequest.getString (field);
}

bool ne7ssh_channel::execCmd(const char* cmd)
{
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    ne7ssh_string packet;

    if (this->_shellSpawned)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Remote shell is running. This command cannot be executed.");
        return false;
    }

    packet.clear();
    packet.addChar(SSH2_MSG_CHANNEL_REQUEST);
    packet.addInt(_session->getSendChannel());
    packet.addString("exec");
    packet.addChar(0);
    packet.addString(cmd);

    if (!transport->sendPacket(packet.value()))
    {
        return false;
    }

    _cmdComplete = false;
    return true;
}

void ne7ssh_channel::getShell()
{
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    ne7ssh_string packet;

    packet.clear();
    packet.addChar(SSH2_MSG_CHANNEL_REQUEST);
    packet.addInt(_session->getSendChannel());
    packet.addString("pty-req");
    packet.addChar(0);
    packet.addString("dumb");
    packet.addInt(80);
    packet.addInt(24);
    packet.addInt(0);
    packet.addInt(0);
    packet.addString("");
    if (!transport->sendPacket(packet.value()))
    {
        return;
    }

    packet.clear();
    packet.addChar(SSH2_MSG_CHANNEL_REQUEST);
    packet.addInt(_session->getSendChannel());
    packet.addString("shell");
    packet.addChar(0);
    if (!transport->sendPacket(packet.value()))
    {
        return;
    }
    this->_shellSpawned = true;
}

void ne7ssh_channel::receive()
{
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    SecureVector<Botan::byte> packet;
    bool notFirst = false;
    short status;

    if (_eof)
    {
        return;
    }

    do
    {
        status = transport->waitForPacket(0, notFirst);
        if (status == -1)
        {
            _eof = true;
            _closed = true;
            _channelOpened = false;
            return;
        }
        if (status != 0)
        {
            if (!notFirst)
            {
                notFirst = true;
            }
            transport->getPacket(packet);
            handleReceived(packet);
        }
    } while (status != 0);
}

bool ne7ssh_channel::handleReceived(Botan::SecureVector<Botan::byte>& _packet)
{
    ne7ssh_string newPacket;
    Botan::byte cmd;

    newPacket.addVector(_packet);
    cmd = newPacket.getByte();
    switch (cmd)
    {
        case SSH2_MSG_CHANNEL_WINDOW_ADJUST:
            adjustWindow(newPacket.value());
            break;

        case SSH2_MSG_CHANNEL_DATA:
            return handleData(newPacket.value());
            break;

        case SSH2_MSG_CHANNEL_EXTENDED_DATA:
            handleExtendedData(newPacket.value());
            break;

        case SSH2_MSG_CHANNEL_EOF:
            return handleEof(newPacket.value());
            break;

        case SSH2_MSG_CHANNEL_CLOSE:
            handleClose(newPacket.value());
            break;

        case SSH2_MSG_CHANNEL_REQUEST:
            handleRequest(newPacket.value());
            break;

        case SSH2_MSG_IGNORE:
            break;

        case SSH2_MSG_DISCONNECT:
            return handleDisconnect(newPacket.value());
            break;

        default:
            ne7ssh::errors()->push(_session->getSshChannel(), "Unhandled command encountered: %i.", cmd);
            return false;
    }
    return true;
}

void ne7ssh_channel::write(Botan::SecureVector<Botan::byte>& data)
{
    SecureVector<Botan::byte> dataBuff, outBuff, delayedBuff;
    uint32 len, maxBytes, i, dataStart;

    if (_delayedBuffer.length())
    {
        dataBuff = _delayedBuffer.value();
        _delayedBuffer.clear();
    }
    dataBuff += data;

    if (!_windowSend)
    {
        delayedBuff = dataBuff;
    }
    else if (_windowSend < dataBuff.size())
    {
        outBuff += SecureVector<Botan::byte>(dataBuff.begin(), _windowSend);
        delayedBuff = SecureVector<Botan::byte>(dataBuff.begin() + _windowSend, dataBuff.size() - _windowSend);
    }
    else
    {
        outBuff += dataBuff;
    }

    if (delayedBuff.size())
    {
        _delayedBuffer.addVector(delayedBuff);
    }
    if (!outBuff.size())
    {
        return;
    }

    len = outBuff.size();
    _windowSend -= len;

    maxBytes = _session->getMaxPacket();
    for (i = 0; len > maxBytes - 64; i++)
    {
        dataStart = maxBytes * i;
        if (i)
        {
            dataStart -= 64;
        }
        dataBuff = SecureVector<Botan::byte>(outBuff.begin() + dataStart, maxBytes - 64);
        _outBuffer.addVector(dataBuff);
        len -= maxBytes - 64;
    }
    if (len)
    {
        dataStart = maxBytes * i;
        if (i)
        {
            dataStart -= 64;
        }
        dataBuff = SecureVector<Botan::byte>(outBuff.begin() + dataStart, len);
        _outBuffer.addVector(dataBuff);
        _inBuffer.clear();
    }
}

void ne7ssh_channel::sendAll()
{
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    SecureVector<Botan::byte> tmpVar;
    ne7ssh_string packet;

    if (!_outBuffer.length() && _delayedBuffer.length())
    {
        tmpVar.swap(_delayedBuffer.value());
        _delayedBuffer.clear();
        write(tmpVar);
    }
    if (!_outBuffer.length())
    {
        return;
    }
    packet.clear();
    packet.addChar(SSH2_MSG_CHANNEL_DATA);
    packet.addInt(_session->getSendChannel());
    packet.addVectorField(_outBuffer.value());

    _windowSend -= _outBuffer.length();
    _inBuffer.clear();
    if (!transport->sendPacket(packet.value()))
    {
        return;
    }
    else
    {
        _outBuffer.clear();
    }
}

bool ne7ssh_channel::adjustRecvWindow(int bufferSize)
{
    _windowRecv -= bufferSize;
    if (_windowRecv == 0)
    {
        sendAdjustWindow();
    }
    return true;
}

