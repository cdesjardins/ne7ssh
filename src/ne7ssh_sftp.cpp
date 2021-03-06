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

#include <sys/stat.h>
#include "ne7ssh_sftp.h"
#include "ne7ssh_sftp_packet.h"
#include "ne7ssh_impl.h"
#include "ne7ssh_session.h"

using namespace Botan;

Ne7sshSftp::Ne7sshSftp(std::shared_ptr<ne7ssh_session> session, std::shared_ptr<ne7ssh_channel> channel)
    : ne7ssh_channel(session),
    _session(session),
    _timeout(30),
    _seq(1),
    _sftpCmd(0),
    _lastError(0)
{
    _windowRecv = channel->getRecvWindow();
    _windowSend = channel->getSendWindow();
}

Ne7sshSftp::~Ne7sshSftp()
{
}

bool Ne7sshSftp::init()
{
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    ne7ssh_string packet;
    bool status;

    packet.clear();
    packet.addChar(SSH2_MSG_CHANNEL_REQUEST);
    packet.addInt(_session->getSendChannel());
    packet.addString("subsystem");
    packet.addChar(0);
    packet.addString("sftp");

    if (!transport->sendPacket(packet.value()))
    {
        return false;
    }

    packet.clear();
    packet.addChar(SSH2_MSG_CHANNEL_DATA);
    packet.addInt(_session->getSendChannel());
    packet.addInt(sizeof(uint32) * 2 + sizeof(char));
    packet.addInt(sizeof(uint32) + sizeof(char));
    packet.addChar(SSH2_FXP_INIT);
    packet.addInt(SFTP_VERSION);

    _windowSend -= 9;

    if (!transport->sendPacket(packet.value()))
    {
        return false;
    }

    _channelOpened = true;
    status = receiveUntil(SSH2_FXP_VERSION, this->_timeout);

    return status;
}

bool Ne7sshSftp::handleData(Botan::SecureVector<Botan::byte>& packet)
{
    ne7ssh_string mainBuffer(packet, 0);
    SecureVector<Botan::byte> sftpBuffer;
    uint32 len = 0;
    Botan::byte cmd;

    mainBuffer.getInt();

    if (!mainBuffer.getString(sftpBuffer))
    {
        return false;
    }
    if (!sftpBuffer.size())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Abnormal. End of stream detected in SFTP subsystem.");
    }

    adjustRecvWindow(sftpBuffer.size());

    if (_seq >= SFTP_MAX_SEQUENCE)
    {
        _seq = 0;
    }

    mainBuffer.clear();

    len = _commBuffer.length();

    if (len)
    {
        mainBuffer.addVector(_commBuffer.value());
    }

    _commBuffer.addVector(sftpBuffer);
    mainBuffer.addVector(sftpBuffer);

    len = mainBuffer.getInt();

    if (len > mainBuffer.length())
    {
        return true;
    }
    else
    {
        _commBuffer.clear();
    }

    cmd = mainBuffer.getByte();

    this->_sftpCmd = cmd;
    switch (cmd)
    {
        case SSH2_FXP_VERSION:
            return handleVersion(mainBuffer.value());

        case SSH2_FXP_HANDLE:
            return addOpenHandle(mainBuffer.value());

        case SSH2_FXP_STATUS:
            return handleStatus(mainBuffer.value());

        case SSH2_FXP_DATA:
            return handleSftpData(mainBuffer.value());

        case SSH2_FXP_NAME:
            return handleNames(mainBuffer.value());

        case SSH2_FXP_ATTRS:
            return processAttrs(mainBuffer.value());

        default:
            ne7ssh::errors()->push(_session->getSshChannel(), "Unhandled SFTP subsystem command: %i.", cmd);
    }

    return false;
}

bool Ne7sshSftp::receiveWindowAdjust()
{
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    SecureVector<Botan::byte> packet;

    if (!transport->waitForPacket(SSH2_MSG_CHANNEL_WINDOW_ADJUST))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Remote side could not adjust the Window.");
        return false;
    }
    transport->getPacket(packet);
    if (!handleReceived(packet))
    {
        return false;
    }
    return true;
}

bool Ne7sshSftp::receiveUntil(uint8 cmd, uint32 timeSec)
{
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    SecureVector<Botan::byte> packet;
    uint32 cutoff = timeSec * 1000000, timeout = 0;
    uint32 prevSize = 0;
    short status;
    bool forever = true;

    this->_sftpCmd = 0;
    _commBuffer.clear();

    while (forever)
    {
        status = transport->waitForPacket(0, false);
        if (status > 0)
        {
            transport->getPacket(packet);
            if (!handleReceived(packet))
            {
                return false;
            }
        }

        if (_commBuffer.length() > prevSize)
        {
            timeout = 0;
        }

        prevSize = _commBuffer.length();

        std::this_thread::sleep_for(std::chrono::milliseconds(1));

        if (_sftpCmd == cmd)
        {
            return true;
        }
        if (!cutoff)
        {
            continue;
        }
        if (timeout >= cutoff)
        {
            break;
        }
        else
        {
            timeout += 10000;
        }
    }
    return false;
}

bool Ne7sshSftp::receiveWhile(uint8 cmd, uint32 timeSec)
{
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    SecureVector<Botan::byte> packet;
    uint32 cutoff = timeSec * 1000000, timeout = 0;
    uint32 prevSize = 0;
    short status;
    bool forever = true;

    this->_sftpCmd = cmd;
    _commBuffer.clear();

    while (forever)
    {
        status = transport->waitForPacket(0, false);
        if (status > 0)
        {
            transport->getPacket(packet);
            if (!handleReceived(packet))
            {
                return false;
            }
        }

        if (_commBuffer.length() > prevSize)
        {
            timeout = 0;
        }
        if (_commBuffer.length() == 0)
        {
            return true;
        }

        prevSize = _commBuffer.length();

        std::this_thread::sleep_for(std::chrono::milliseconds(1));

        if (_sftpCmd != cmd)
        {
            return true;
        }

        if (!cutoff)
        {
            continue;
        }
        if (timeout >= cutoff)
        {
            break;
        }
        else
        {
            timeout += 10000;
        }
    }
    return false;
}

bool Ne7sshSftp::handleVersion(Botan::SecureVector<Botan::byte>& packet)
{
    ne7ssh_string sftpBuffer(packet, 0);
    uint32 version;

    version = sftpBuffer.getInt();

    if (version != SFTP_VERSION)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Unsupported SFTP version: %i.", version);
        return false;
    }

    return true;
}

bool Ne7sshSftp::handleStatus(Botan::SecureVector<Botan::byte>& packet)
{
    ne7ssh_string sftpBuffer(packet, 0);
    uint32 errorID;
    SecureVector<Botan::byte> errorStr;

    sftpBuffer.getInt();
    errorID = sftpBuffer.getInt();
    sftpBuffer.getString(errorStr);

    if (errorID)
    {
        _lastError = (uint8)errorID;
        ne7ssh::errors()->push(_session->getSshChannel(), "SFTP Error code: <%i>, description: %s.", errorID, errorStr.begin());
        return false;
    }
    return true;
}

bool Ne7sshSftp::addOpenHandle(Botan::SecureVector<Botan::byte>& packet)
{
    ne7ssh_string sftpBuffer(packet, 0);
    uint32 requestID;
    SecureVector<Botan::byte> handle;

    requestID = sftpBuffer.getInt();
    sftpBuffer.getString(handle);

    sftpFile file;
    file.fileID = requestID;
    file._handle.assign((char*)handle.begin(), handle.size());
    sftpFiles.push_back(file);

    return true;
}

bool Ne7sshSftp::handleSftpData(Botan::SecureVector<Botan::byte>& packet)
{
    ne7ssh_string sftpBuffer(packet, 0);
    SecureVector<Botan::byte> data;

    sftpBuffer.getInt();
    sftpBuffer.getString(data);

    if (data.size() == 0)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Abnormal. End of stream detected.");
        return false;
    }

    _commBuffer.clear();
    _fileBuffer.clear();
    _fileBuffer.swap(data);
    return true;
}

bool Ne7sshSftp::handleNames(Botan::SecureVector<Botan::byte>& packet)
{
    Ne7sshSftpPacket sftpBuffer(packet, 0);
    ne7ssh_string tmpVar;
    uint32 fileCount, i;
    SecureVector<Botan::byte> fileName;

    sftpBuffer.getInt();
    fileCount = sftpBuffer.getInt();
    tmpVar.addInt(fileCount);

    if (!fileCount)
    {
        return true;
    }

    for (i = 0; i < fileCount; i++)
    {
        sftpBuffer.getString(fileName);
        tmpVar.addVectorField(fileName);
        sftpBuffer.getString(fileName);
        tmpVar.addVectorField(fileName);
        _attrs.flags = sftpBuffer.getInt();
        if (_attrs.flags & SSH2_FILEXFER_ATTR_SIZE)
        {
            _attrs.size = sftpBuffer.getInt64();
        }

        if (_attrs.flags & SSH2_FILEXFER_ATTR_UIDGID)
        {
            _attrs.owner = sftpBuffer.getInt();
            _attrs.group = sftpBuffer.getInt();
        }

        if (_attrs.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
        {
            _attrs.permissions = sftpBuffer.getInt();
        }

        if (_attrs.flags & SSH2_FILEXFER_ATTR_ACMODTIME)
        {
            _attrs.atime = sftpBuffer.getInt();
            _attrs.mtime = sftpBuffer.getInt();
        }
    }
    _fileBuffer += tmpVar.value();

    return true;
}

bool Ne7sshSftp::processAttrs(Botan::SecureVector<Botan::byte>& packet)
{
    Ne7sshSftpPacket sftpBuffer(packet, 0);
    SecureVector<Botan::byte> data;

    sftpBuffer.getInt();
    _attrs.flags = sftpBuffer.getInt();
    if (_attrs.flags & SSH2_FILEXFER_ATTR_SIZE)
    {
        _attrs.size = sftpBuffer.getInt64();
    }

    if (_attrs.flags & SSH2_FILEXFER_ATTR_UIDGID)
    {
        _attrs.owner = sftpBuffer.getInt();
        _attrs.group = sftpBuffer.getInt();
    }

    if (_attrs.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
    {
        _attrs.permissions = sftpBuffer.getInt();
    }

    if (_attrs.flags & SSH2_FILEXFER_ATTR_ACMODTIME)
    {
        _attrs.atime = sftpBuffer.getInt();
        _attrs.mtime = sftpBuffer.getInt();
    }

    return true;
}

uint32 Ne7sshSftp::openFile(const char* filename, uint8 shortMode)
{
    uint32 mode;
    Ne7sshSftpPacket packet(_session->getSendChannel());
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    bool status;
    ne7ssh_string fullPath;

    fullPath = getFullPath(filename);

    if (!fullPath.length())
    {
        return 0;
    }

    switch (shortMode)
    {
        case READ:
            mode = SSH2_FXF_READ;
            break;

        case OVERWRITE:
            mode = SSH2_FXF_WRITE | SSH2_FXF_CREAT | SSH2_FXF_TRUNC;
            break;

        case APPEND:
            mode = SSH2_FXF_WRITE | SSH2_FXF_CREAT;
            break;

        default:
            ne7ssh::errors()->push(_session->getSshChannel(), "Unsupported file opening mode: %i.", shortMode);
            return 0;
    }

    packet.addChar(SSH2_FXP_OPEN);
    packet.addInt(this->_seq++);
    packet.addVectorField(fullPath.value());
    packet.addInt(mode);
    packet.addInt(0);

    if (!packet.isChannelSet())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Channel not set in sftp packet class.");
        return 0;
    }

    if (!transport->sendPacket(packet.value()))
    {
        return 0;
    }

    _windowSend -= 21 + fullPath.length();

    status = receiveUntil(SSH2_FXP_HANDLE, this->_timeout);

    if (!status)
    {
        return 0;
    }
    else
    {
        return (_seq - 1);
    }
}

uint32 Ne7sshSftp::openDir(const char* dirname)
{
    Ne7sshSftpPacket packet(_session->getSendChannel());
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    bool status;
    ne7ssh_string fullPath = getFullPath(dirname);

    if (!fullPath.length())
    {
        return 0;
    }

    packet.addChar(SSH2_FXP_OPENDIR);
    packet.addInt(this->_seq++);
    packet.addVectorField(fullPath.value());

    if (!packet.isChannelSet())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Channel not set in sftp packet class.");
        return 0;
    }

    if (!transport->sendPacket(packet.value()))
    {
        return 0;
    }

    _windowSend -= 13 + fullPath.length();

    status = receiveUntil(SSH2_FXP_HANDLE, this->_timeout);

    if (!status)
    {
        return 0;
    }
    else
    {
        return (_seq - 1);
    }
}

bool Ne7sshSftp::readFile(uint32 fileID, uint64 offset)
{
    Ne7sshSftpPacket packet(_session->getSendChannel());
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    bool status;
    sftpFile* remoteFile = getFileHandle(fileID);

    if (!remoteFile)
    {
        return false;
    }

    packet.addChar(SSH2_FXP_READ);
    packet.addInt(this->_seq++);
    packet.addInt(remoteFile->_handle.length());
    packet.addBytes((Botan::byte*)remoteFile->_handle.c_str(), remoteFile->_handle.length());
    packet.addInt64(offset);
    packet.addInt(SFTP_MAX_MSG_SIZE);

    if (!packet.isChannelSet())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Channel not set in sftp packet class.");
        return 0;
    }

    if (!transport->sendPacket(packet.value()))
    {
        return false;
    }

    _windowSend -= remoteFile->_handle.length() + 25;

    status = receiveWhile(SSH2_FXP_DATA, this->_timeout);

    return status;
}

bool Ne7sshSftp::writeFile(uint32 fileID, const uint8* data, uint32 len, uint64 offset)
{
    Ne7sshSftpPacket packet(_session->getSendChannel());
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    bool status;
    sftpFile* remoteFile = getFileHandle(fileID);
    uint32 sent = 0, currentLen = 0;
    Botan::SecureVector<Botan::byte> sendVector;

    if (len > SFTP_MAX_MSG_SIZE)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Could not write. Datablock larger than maximum msg size. Remote file ID %i.", fileID);
        return false;
    }

    if (!remoteFile)
    {
        return false;
    }

    packet.addChar(SSH2_FXP_WRITE);
    packet.addInt(this->_seq++);
    packet.addInt(remoteFile->_handle.length());
    packet.addBytes((Botan::byte*)remoteFile->_handle.c_str(), remoteFile->_handle.length());
    packet.addInt64(offset);
    packet.addInt(len);

    if (!packet.isChannelSet())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Channel not set in sftp packet class.");
        return false;
    }
    _windowSend -= remoteFile->_handle.length() + 25;

    while (sent < len)
    {
        currentLen = len - sent < _windowSend ? len - sent : _windowSend;
        currentLen = currentLen < (uint32)(SFTP_MAX_PACKET_SIZE - (remoteFile->_handle.length() + 86)) ? currentLen : SFTP_MAX_PACKET_SIZE - (remoteFile->_handle.length() + 86);

        if (sent)
        {
            packet.clear();
        }
        packet.addBytes(data + sent, currentLen);

        if (sent)
        {
            sendVector = packet.valueFragment();
        }
        else
        {
            sendVector = packet.valueFragment(remoteFile->_handle.length() + 21 + len);
        }

        if (!sendVector.size())
        {
            return false;
        }

        status = transport->sendPacket(sendVector);
        if (!status)
        {
            return false;
        }

        _windowSend -= currentLen;
        sent += currentLen;
        if (!_windowSend)
        {
            if (!receiveWindowAdjust())
            {
                ne7ssh::errors()->push(_session->getSshChannel(), "Remote side could not adjust the Window.");
                return false;
            }
        }
//    if (sent - currentLen) break;
    }
    status = receiveUntil(SSH2_FXP_STATUS, this->_timeout);
    return status;
}

bool Ne7sshSftp::closeFile(uint32 fileID)
{
    Ne7sshSftpPacket packet(_session->getSendChannel());
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    uint16 i;
    bool status;
    sftpFile* remoteFile = getFileHandle(fileID);

    if (!remoteFile)
    {
        return false;
    }

    packet.addChar(SSH2_FXP_CLOSE);
    packet.addInt(this->_seq++);
    packet.addInt(remoteFile->_handle.length());
    packet.addBytes((Botan::byte*)remoteFile->_handle.c_str(), remoteFile->_handle.length());

    if (!packet.isChannelSet())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Channel not set in sftp packet class.");
        return 0;
    }

    if (!transport->sendPacket(packet.value()))
    {
        return false;
    }

    _windowSend -= remoteFile->_handle.length() + 13;

    for (i = 0; i < sftpFiles.size(); i++)
    {
        if (sftpFiles[i].fileID == fileID)
        {
            sftpFiles.erase(sftpFiles.begin() + i);
            break;
        }
    }

    status = receiveUntil(SSH2_FXP_STATUS, this->_timeout);
    return status;
}

ne7ssh_string Ne7sshSftp::getFullPath(const char* filename)
{
    Botan::SecureVector<Botan::byte> result;
    std::string buffer;
    uint32 len, pos, last_char, i = 0;

    if (!filename)
    {
        return ne7ssh_string();
    }
    len = strlen(filename);

    buffer.assign(filename, len);

    while (isspace(buffer[i]))
    {
        i++;
    }

    for (pos = 0; i < len; i++)
    {
        if (buffer[i] == '\\')
        {
            buffer[pos] = '/';
        }
        else
        {
            buffer[pos] = buffer[i];
        }
        pos++;
    }
    pos--;
    while (isspace(buffer[pos]))
    {
        pos--;
    }
    if (pos > 1 && buffer[pos] == '.' && buffer[pos - 1] != '.')
    {
        pos--;
    }
    else if (!pos && buffer[pos] == '.')
    {
        buffer[pos] = 0;
    }

    result.clear();
    if ((buffer[0] != '/') && (_currentPath.length() > 0))
    {
        if (_currentPath.length() > 0)
        {
            len = this->_currentPath.length();
        }
        else
        {
            return ne7ssh_string();
        }
        result += SecureVector<Botan::byte>((uint8*)_currentPath.c_str(), len);
        last_char = len - 1;
        if (_currentPath[last_char] && _currentPath[last_char] != '/')
        {
            result += SecureVector<Botan::byte>((uint8*)"/", 1);
        }
    }
    while (buffer[pos] == '/')
    {
        pos--;
    }
    buffer[++pos] = 0x00;
    result += SecureVector<Botan::byte>((uint8*)buffer.c_str(), pos);
    return ne7ssh_string(result, 0);
}

Ne7sshSftp::sftpFile* Ne7sshSftp::getFileHandle(uint32 fileID)
{
    uint16 i;

    for (i = 0; i < sftpFiles.size(); i++)
    {
        if (sftpFiles[i].fileID == fileID)
        {
            return &sftpFiles[i];
        }
    }
    ne7ssh::errors()->push(_session->getSshChannel(), "Invalid file ID: %i.", fileID);
    return 0;
}

bool Ne7sshSftp::getFileStats(const char* remoteFile, bool followSymLinks)
{
    Ne7sshSftpPacket packet(_session->getSendChannel());
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    bool status;
    uint8 cmd = followSymLinks ? SSH2_FXP_STAT : SSH2_FXP_LSTAT;
    ne7ssh_string fullPath = getFullPath(remoteFile);

    if (!fullPath.length())
    {
        return 0;
    }

    if (!remoteFile)
    {
        return false;
    }

    packet.addChar(cmd);
    packet.addInt(this->_seq++);
    packet.addVectorField(fullPath.value());
    packet.addInt(SSH2_FILEXFER_ATTR_SIZE | SSH2_FILEXFER_ATTR_UIDGID | SSH2_FILEXFER_ATTR_PERMISSIONS | SSH2_FILEXFER_ATTR_ACMODTIME);

    if (!packet.isChannelSet())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Channel not set in sftp packet class.");
        return 0;
    }

    if (!transport->sendPacket(packet.value()))
    {
        return false;
    }

    _windowSend -= 17 + fullPath.length();

    status = receiveWhile(SSH2_FXP_ATTRS, this->_timeout);
    return status;
}

bool Ne7sshSftp::getFStat(uint32 fileID)
{
    Ne7sshSftpPacket packet(_session->getSendChannel());
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    bool status;
    sftpFile* remoteFile = getFileHandle(fileID);

    if (!remoteFile)
    {
        return false;
    }
    packet.addChar(SSH2_FXP_FSTAT);
    packet.addInt(this->_seq++);
    packet.addInt(remoteFile->_handle.length());
    packet.addBytes((Botan::byte*)remoteFile->_handle.c_str(), remoteFile->_handle.length());

    if (!packet.isChannelSet())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Channel not set in sftp packet class.");
        return 0;
    }

    if (!transport->sendPacket(packet.value()))
    {
        return false;
    }

    _windowSend -= remoteFile->_handle.length() + 13;

    status = receiveWhile(SSH2_FXP_ATTRS, this->_timeout);
    return status;
}

uint64 Ne7sshSftp::getFileSize(uint32 fileID)
{
    if (!getFStat(fileID))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Failed to get remote file attributes.");
        return 0;
    }

    return _attrs.size;
}

bool Ne7sshSftp::getFileAttrs(Ne7SftpSubsystem::fileAttrs& attributes, const char* remoteFile, bool followSymLinks)
{
    if (!remoteFile)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Failed to get remote file attributes.");
        return false;
    }
    ne7ssh_string fullPath = getFullPath(remoteFile);
    if (!fullPath.length())
    {
        return false;
    }

    if (!getFileStats((const char*)fullPath.value().begin(), followSymLinks))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Failed to get remote file attributes.");
        return false;
    }

    attributes.size = _attrs.size;
    attributes.owner = _attrs.owner;
    attributes.group = _attrs.group;
    attributes.permissions = _attrs.permissions;
    attributes.atime = _attrs.atime;
    attributes.mtime = _attrs.mtime;

    return true;
}

bool Ne7sshSftp::getFileAttrs(sftpFileAttrs& attributes, Botan::SecureVector<Botan::byte>& remoteFile, bool followSymLinks)
{
    if (!remoteFile.size())
    {
        return false;
    }
    if (!getFileStats((const char*)remoteFile.begin(), followSymLinks))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Failed to get remote file attributes.");
        return false;
    }
    attributes.size = _attrs.size;
    attributes.owner = _attrs.owner;
    attributes.group = _attrs.group;
    attributes.permissions = _attrs.permissions;
    attributes.atime = _attrs.atime;
    attributes.mtime = _attrs.mtime;

    return true;
}

bool Ne7sshSftp::isType(const char* remoteFile, uint32 type)
{
    uint32 perms;
    if (!remoteFile)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Failed to get remote file attributes.");
        return false;
    }
    ne7ssh_string fullPath = getFullPath(remoteFile);
    if (!fullPath.length())
    {
        return false;
    }

    if (!getFileStats((const char*)fullPath.value().begin()))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Failed to get remote file attributes.");
        return false;
    }

    perms = _attrs.permissions;
    if (perms & type)
    {
        return true;
    }
    else
    {
        return false;
    }
}

bool Ne7sshSftp::isFile(const char* remoteFile)
{
    return isType(remoteFile, S_IFREG);
}

bool Ne7sshSftp::isDir(const char* remoteFile)
{
    return isType(remoteFile, S_IFDIR);
}

bool Ne7sshSftp::get(const char* remoteFile, FILE* localFile)
{
    uint64 size;
    uint64 offset = 0;
    Botan::SecureVector<Botan::byte> localBuffer;
    uint32 fileID;

    if (!localFile)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Invalid local or remote file.");
        return false;
    }

    fileID = openFile(remoteFile, READ);

    if (!fileID)
    {
        return false;
    }

    size = getFileSize(fileID);

    if (!size)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "File size is zero.");
        return false;
    }

    while (size > offset)
    {
        readFile(fileID, offset);
        if (_fileBuffer.size() == 0)
        {
            return false;
        }
        localBuffer.clear();
        localBuffer.swap(_fileBuffer);

        if (!fwrite(localBuffer.begin(), (size_t) localBuffer.size(), 1, localFile))
        {
            ne7ssh::errors()->push(_session->getSshChannel(), "Could not write to local file. Remote file ID %i.", fileID);
            return false;
        }
        offset += localBuffer.size();
    }

    if (!closeFile(fileID))
    {
        return false;
    }
    return true;
}

bool Ne7sshSftp::put(FILE* localFile, const char* remoteFile)
{
    size_t size;
    size_t offset = 0;
    Botan::SecureVector<Botan::byte> localBuffer;
    uint32 fileID;
    size_t len;

    if (!localFile || !remoteFile)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Invalid local or remote file.");
        return false;
    }

    fileID = openFile(remoteFile, OVERWRITE);

    if (!fileID)
    {
        return false;
    }

    fseek(localFile, 0L, SEEK_END);
    size = ftell(localFile);
    rewind(localFile);

    if (!size)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "File size is zero.");
        return false;
    }

    std::unique_ptr<uint8> buffer(new uint8[SFTP_MAX_MSG_SIZE]);
    while (size > offset)
    {
        len = (size - offset) < SFTP_MAX_MSG_SIZE - 384 ? (size - offset) : SFTP_MAX_MSG_SIZE - 384;

        if (!fread(buffer.get(), len, 1, localFile))
        {
            ne7ssh::errors()->push(_session->getSshChannel(), "Could not read from local file. Remote file ID %i.", fileID);
            return false;
        }
        if (!writeFile(fileID, buffer.get(), len, offset))
        {
            return false;
        }
        offset += len;
    }

    if (!closeFile(fileID))
    {
        return false;
    }
    return true;
}

bool Ne7sshSftp::rm(const char* remoteFile)
{
    Ne7sshSftpPacket packet(_session->getSendChannel());
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    bool status;
    if (!remoteFile)
    {
        return false;
    }
    ne7ssh_string fullPath = getFullPath(remoteFile);

    if (!fullPath.length())
    {
        return false;
    }

    packet.addChar(SSH2_FXP_REMOVE);
    packet.addInt(this->_seq++);
    packet.addVectorField(fullPath.value());

    if (!packet.isChannelSet())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Channel not set in sftp packet class.");
        return false;
    }

    if (!transport->sendPacket(packet.value()))
    {
        return false;
    }

    _windowSend -= 13 + fullPath.length();

    status = receiveWhile(SSH2_FXP_STATUS, this->_timeout);
    return status;
}

bool Ne7sshSftp::mv(const char* oldFile, const char* newFile)
{
    Ne7sshSftpPacket packet(_session->getSendChannel());
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    bool status;
    if (!oldFile || !newFile)
    {
        return false;
    }
    ne7ssh_string oldPath = getFullPath(oldFile);
    ne7ssh_string newPath = getFullPath(newFile);

    if (!oldPath.length() || !newPath.length())
    {
        return false;
    }

    packet.addChar(SSH2_FXP_RENAME);
    packet.addInt(this->_seq++);
    packet.addVectorField(oldPath.value());
    packet.addVectorField(newPath.value());

    if (!packet.isChannelSet())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Channel not set in sftp packet class.");
        return 0;
    }

    if (!transport->sendPacket(packet.value()))
    {
        return false;
    }

    _windowSend -= oldPath.length() + newPath.length() + 17;

    status = receiveWhile(SSH2_FXP_STATUS, this->_timeout);
    return status;
}

bool Ne7sshSftp::mkdir(const char* remoteDir)
{
    Ne7sshSftpPacket packet(_session->getSendChannel());
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    bool status;
    if (!remoteDir)
    {
        return false;
    }
    ne7ssh_string fullPath = getFullPath(remoteDir);

    if (!fullPath.length())
    {
        return false;
    }

    packet.addChar(SSH2_FXP_MKDIR);
    packet.addInt(this->_seq++);
    packet.addVectorField(fullPath.value());
    packet.addInt(0);

    if (!packet.isChannelSet())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Channel not set in sftp packet class.");
        return 0;
    }

    if (!transport->sendPacket(packet.value()))
    {
        return false;
    }

    _windowSend -= fullPath.length() + 17;

    status = receiveWhile(SSH2_FXP_STATUS, this->_timeout);
    return status;
}

bool Ne7sshSftp::rmdir(const char* remoteDir)
{
    Ne7sshSftpPacket packet(_session->getSendChannel());
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    bool status;
    if (!remoteDir)
    {
        return false;
    }
    ne7ssh_string fullPath = getFullPath(remoteDir);

    if (!fullPath.length())
    {
        return false;
    }

    packet.addChar(SSH2_FXP_RMDIR);
    packet.addInt(this->_seq++);
    packet.addVectorField(fullPath.value());

    if (!packet.isChannelSet())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Channel not set in sftp packet class.");
        return 0;
    }

    if (!transport->sendPacket(packet.value()))
    {
        return false;
    }

    _windowSend -= fullPath.length() + 13;

    status = receiveWhile(SSH2_FXP_STATUS, this->_timeout);
    return status;
}

const char* Ne7sshSftp::ls(const char* remoteDir, bool longNames)
{
    Ne7sshSftpPacket packet(_session->getSendChannel());
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    ne7ssh_string tmpVar;
    SecureVector<Botan::byte> fileName;
    bool status = true;
    uint32 fileID, fileCount, i;
    sftpFile* remoteFile;
    if (!remoteDir)
    {
        return 0;
    }

    fileID = openDir(remoteDir);

    if (!fileID)
    {
        return 0;
    }
    remoteFile = getFileHandle(fileID);
    if (!remoteFile)
    {
        return 0;
    }
    _fileBuffer.clear();

    while (status)
    {
        packet.clear();
        packet.addChar(SSH2_FXP_READDIR);
        packet.addInt(this->_seq++);
        packet.addInt(remoteFile->_handle.length());
        packet.addBytes((Botan::byte*)remoteFile->_handle.c_str(), remoteFile->_handle.length());

        if (!packet.isChannelSet())
        {
            ne7ssh::errors()->push(_session->getSshChannel(), "Channel not set in sftp packet class.");
            return 0;
        }

        if (!transport->sendPacket(packet.value()))
        {
            return 0;
        }

        _windowSend -= remoteFile->_handle.length() + 13;

        status = receiveWhile(SSH2_FXP_NAME, this->_timeout);
    }
    if (_lastError > 1)
    {
        return 0;
    }

    packet.clear();
    packet.addVector(_fileBuffer);
    fileCount = packet.getInt();
    tmpVar.clear();
    for (i = 0; i < fileCount; i++)
    {
        packet.getString(fileName);
        fileName += SecureVector<Botan::byte>((const Botan::byte*)"\n", 1);
        if (!longNames)
        {
            tmpVar.addVector(fileName);
        }

        packet.getString(fileName);
        fileName += SecureVector<Botan::byte>((const Botan::byte*)"\n", 1);
        if (longNames)
        {
            tmpVar.addVector(fileName);
        }
    }
    _fileBuffer.swap(tmpVar.value());

    if (!closeFile(fileID))
    {
        return 0;
    }
    return (const char*)_fileBuffer.begin();
}

bool Ne7sshSftp::cd(const char* remoteDir)
{
    Ne7sshSftpPacket packet(_session->getSendChannel());
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    SecureVector<Botan::byte> fileName;
    uint32 fileCount;
    bool status;
    if (!remoteDir)
    {
        return false;
    }
    ne7ssh_string fullPath = getFullPath(remoteDir);

    if (!fullPath.length())
    {
        return false;
    }

    _fileBuffer.clear();

    packet.addChar(SSH2_FXP_REALPATH);
    packet.addInt(this->_seq++);
    packet.addVectorField(fullPath.value());

    if (!packet.isChannelSet())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Channel not set in sftp packet class.");
        return false;
    }

    if (!transport->sendPacket(packet.value()))
    {
        return false;
    }

    _windowSend -= fullPath.length() + 13;

    status = receiveWhile(SSH2_FXP_NAME, this->_timeout);
    if (!status)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Could not change to remote directory: %s.", remoteDir);
        return false;
    }

    packet.clear();
    packet.addVector(_fileBuffer);
    fileCount = packet.getInt();
    if (!fileCount)
    {
        return false;
    }
    packet.getString(fileName);

    _currentPath.assign((char*)fileName.begin(), fileName.size());
    return status;
}

bool Ne7sshSftp::chmod(const char* remoteFile, const char* mode)
{
    Ne7sshSftpPacket packet(_session->getSendChannel());
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    bool status;
    if (!remoteFile)
    {
        return false;
    }
    ne7ssh_string fullPath = getFullPath(remoteFile);
    uint32 perms, len, octet = 0;
    bool u, g, o, plus;
    const char* pos;
    uint8 i;
    char converter[] = {'0', '0', '0', '0', '0'};

    if (!fullPath.length())
    {
        return false;
    }

    if (!getFileAttrs(_attrs, fullPath.value(), true))
    {
        return false;
    }

    perms = _attrs.permissions;

    len = strlen(mode);
    if (len < 5 && len > 2)
    {
        for (i = 0; i < len; i++)
        {
            if (!isdigit(mode[i]))
            {
                break;
            }
        }

        if (i != len)
        {
            pos = mode;
        }
        else
        {
            memcpy(converter + (5 - len), mode, len);
            octet = strtol(converter, (char**)&pos, 8);
            if (octet > 07777)
            {
                ne7ssh::errors()->push(_session->getSshChannel(), "Invalid permission octet.");
                return false;
            }
            if (len == 3)
            {
                perms = (perms & ~0777) | octet;
            }
            else
            {
                perms = (perms & ~07777) | octet;
            }
        }
    }

    pos = mode;
    if (!octet)
    {
        while (*pos)
        {
            if (*pos == ',')
            {
                pos++;
            }
            u = g = o = plus = false;
            while (*pos && *pos != '+' && *pos != '-')
            {
                switch (*pos)
                {
                    case 'u':
                        u = true;
                        break;

                    case 'g':
                        g = true;
                        break;

                    case 'o':
                        o = true;
                        break;

                    case 'a':
                        u = g = o = true;
                        break;

                    default:
                        ne7ssh::errors()->push(_session->getSshChannel(), "Invalid mode string.");
                        return false;
                }
                pos++;
            }

            if (*pos == '+')
            {
                plus = true;
            }
            pos++;
            while (*pos && *pos != ',')
            {
                switch (*pos)
                {
                    case 'r':
                        if (u)
                        {
                            perms = plus ?  perms | S_IRUSR : perms ^ S_IRUSR;
                        }
                        if (g)
                        {
                            perms = plus ?  perms | S_IRGRP : perms ^ S_IRGRP;
                        }
                        if (o)
                        {
                            perms = plus ?  perms | S_IROTH : perms ^ S_IROTH;
                        }
                        break;

                    case 'w':
                        if (u)
                        {
                            perms = plus ?  perms | S_IWUSR : perms ^ S_IWUSR;
                        }
                        if (g)
                        {
                            perms = plus ?  perms | S_IWGRP : perms ^ S_IWGRP;
                        }
                        if (o)
                        {
                            perms = plus ?  perms | S_IWOTH : perms ^ S_IWOTH;
                        }
                        break;

                    case 'x':
                        if (u)
                        {
                            perms = plus ?  perms | S_IXUSR : perms ^ S_IXUSR;
                        }
                        if (g)
                        {
                            perms = plus ?  perms | S_IXGRP : perms ^ S_IXGRP;
                        }
                        if (o)
                        {
                            perms = plus ?  perms | S_IXOTH : perms ^ S_IXOTH;
                        }
                        break;

                    case 's':
                        if (u)
                        {
                            perms = plus ?  perms | S_ISUID : perms ^ S_ISUID;
                        }
                        if (g)
                        {
                            perms = plus ?  perms | S_ISGID : perms ^ S_ISGID;
                        }
                        break;

                    case 't':
                        perms = plus ?  perms | S_ISVTX : perms ^ S_ISVTX;
                        break;

                    case 'X':
                        if ((perms & 111) == 0)
                        {
                            break;
                        }
                        if (u)
                        {
                            perms = plus ?  perms | S_IXUSR : perms ^ S_IXUSR;
                        }
                        if (g)
                        {
                            perms = plus ?  perms | S_IXGRP : perms ^ S_IXGRP;
                        }
                        if (o)
                        {
                            perms = plus ?  perms | S_IXOTH : perms ^ S_IXOTH;
                        }
                        break;

                    case 'u':
                        if (u)
                        {
                            perms = plus ?  perms | (perms & S_IRWXU) : perms ^ (perms & S_IRWXU);
                        }
                        if (g)
                        {
                            perms = plus ?  perms | (perms & S_IRWXU) : perms ^ (perms & S_IRWXU);
                        }
                        if (o)
                        {
                            perms = plus ?  perms | (perms & S_IRWXU) : perms ^ (perms & S_IRWXU);
                        }
                        break;

                    case 'g':
                        if (u)
                        {
                            perms = plus ?  perms | (perms & S_IRWXG) : perms ^ (perms & S_IRWXG);
                        }
                        if (g)
                        {
                            perms = plus ?  perms | (perms & S_IRWXG) : perms ^ (perms & S_IRWXG);
                        }
                        if (o)
                        {
                            perms = plus ?  perms | (perms & S_IRWXG) : perms ^ (perms & S_IRWXG);
                        }
                        break;

                    case 'o':
                        if (u)
                        {
                            perms = plus ?  perms | (perms & S_IRWXO) : perms ^ (perms & S_IRWXO);
                        }
                        if (g)
                        {
                            perms = plus ?  perms | (perms & S_IRWXO) : perms ^ (perms & S_IRWXO);
                        }
                        if (o)
                        {
                            perms = plus ?  perms | (perms & S_IRWXO) : perms ^ (perms & S_IRWXO);
                        }
                        break;

                    default:
                        ne7ssh::errors()->push(_session->getSshChannel(), "Invalid mode string.");
                        return false;
                }
                pos++;
            }
        }
    }

    packet.addChar(SSH2_FXP_SETSTAT);
    packet.addInt(this->_seq++);
    packet.addVectorField(fullPath.value());
    packet.addInt(SSH2_FILEXFER_ATTR_PERMISSIONS);
    packet.addInt(perms);

    if (!packet.isChannelSet())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Channel not set in sftp packet class.");
        return 0;
    }

    if (!transport->sendPacket(packet.value()))
    {
        return false;
    }

    _windowSend -= fullPath.length() + 21;

    status = receiveWhile(SSH2_FXP_STATUS, this->_timeout);
    return status;
}

bool Ne7sshSftp::chown(const char* remoteFile, uint32 uid, uint32 gid)
{
    Ne7sshSftpPacket packet(_session->getSendChannel());
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    bool status;
    uint32 old_uid, old_gid;
    if (!remoteFile)
    {
        return false;
    }
    ne7ssh_string fullPath = getFullPath(remoteFile);

    if (!fullPath.length())
    {
        return false;
    }

    if (!getFileAttrs(_attrs, fullPath.value(), true))
    {
        return false;
    }

    old_uid = _attrs.owner;
    old_gid = _attrs.group;

    packet.addChar(SSH2_FXP_SETSTAT);
    packet.addInt(this->_seq++);
    packet.addVectorField(fullPath.value());
    packet.addInt(SSH2_FILEXFER_ATTR_UIDGID);
    if (uid)
    {
        packet.addInt(uid);
    }
    else
    {
        packet.addInt(old_uid);
    }
    if (gid)
    {
        packet.addInt(gid);
    }
    else
    {
        packet.addInt(old_gid);
    }

    if (!packet.isChannelSet())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Channel not set in sftp packet class.");
        return false;
    }

    if (!transport->sendPacket(packet.value()))
    {
        return false;
    }

    _windowSend -= fullPath.length() + 25;

    status = receiveWhile(SSH2_FXP_STATUS, this->_timeout);
    return status;
}

