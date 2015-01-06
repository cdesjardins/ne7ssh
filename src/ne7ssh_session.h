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

#ifndef NE7SSH_SESSION_H
#define NE7SSH_SESSION_H

#include "ne7ssh_types.h"
#include "ne7ssh_transport.h"
#include "crypt.h"

/**
@author Andrew Useckas
*/
class ne7ssh_session
{
private:
    Botan::SecureVector<Botan::byte> _localVersion;
    Botan::SecureVector<Botan::byte> _remoteVersion;
    Botan::SecureVector<Botan::byte> _sessionID;
    uint32 _sendChannel;
    uint32 _receiveChannel;
    uint32 _maxPacket;
    int32 _channelID;

public:
    std::shared_ptr<ne7ssh_transport> _transport;
    std::shared_ptr<ne7ssh_crypt> _crypto;

    /**
     * ne7ssh_session class constructor.
     */
    ne7ssh_session();

    /**
     * ne7ssh_session class desctructor.
     */
    ~ne7ssh_session();

    /**
     * Sets the local SSH version string.
     * @param version Reference to a vector containing the version string.
     */
    void setLocalVersion(Botan::SecureVector<Botan::byte>& version)
    {
        _localVersion = version;
    }

    /**
     * Returns local SSH version.
     * @return Reference to a vector containing the version string.
     */
    Botan::SecureVector<Botan::byte> &getLocalVersion()
    {
        return _localVersion;
    }

    /**
     * Sets the remote SSH version string.
     * @param version Reference to a vector containing the version string.
     */
    void setRemoteVersion(Botan::SecureVector<Botan::byte>& version)
    {
        _remoteVersion = version;
    }

    /**
     * Returns remote SSH version.
     * @return Reference to a vector containing the version string.
     */
    Botan::SecureVector<Botan::byte> &getRemoteVersion()
    {
        return _remoteVersion;
    }

    /**
     * Sets SSH session ID, a.k.a. H from the first KEX.
     * @param session Reference to a vector containing the session ID.
     */
    void setSessionID(Botan::SecureVector<Botan::byte>& session)
    {
        _sessionID = session;
    }

    /**
     * Returns the current SSH session ID.
     * @return Reference to a vector containing the session ID.
     */
    Botan::SecureVector<Botan::byte> &getSessionID()
    {
        return _sessionID;
    }

    /**
     * After the channel is open this function sets the send channel ID.
     * @param channel Channel ID.
     */
    void setSendChannel(uint32 channel)
    {
        _sendChannel = channel;
    }

    /**
     * Returns the send channel ID.
     * @return Channel ID.
     */
    uint32 getSendChannel() const
    {
        return _sendChannel;
    }

    /**
     * After the channel is open this function sets the receive channel ID.
     * @param channel Channel ID.
     */
    void setReceiveChannel(uint32 channel)
    {
        _receiveChannel = channel;
    }

    /**
     * Returns the receive channel ID.
     * @return Channel ID.
     */
    uint32 getReceiveChannel()
    {
        return _receiveChannel;
    }

    /**
     * Sets maximum send packet size.
     * @param size Maximum packet size.
     */
    void setMaxPacket(uint32 size)
    {
        _maxPacket = size;
    }

    /**
     * Returns maximum send packet size.
     * @return Maximum packet size.
     */
    uint32 getMaxPacket()
    {
        return _maxPacket;
    }

    /**
     * Stores newly created ne7ssh channel.
     * @param channel ne7ssh channel.
     */
    void setSshChannel(int32 channel)
    {
        _channelID = channel;
    }

    /**
     * REtrieves current ne7ssh channel.
     * @return ne7ssh channel or -1 if the session hasn't succesfully opened the channel yet.
     */
    int32 getSshChannel()
    {
        return _channelID;
    }
};

#endif
