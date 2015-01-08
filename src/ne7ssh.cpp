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

#include "ne7ssh.h"
#include "ne7ssh_sftp.h"
#include "ne7ssh_impl.h"

std::shared_ptr<ne7ssh_impl> ne7ssh::s_ne7sshInst;

void ne7ssh::create()
{
    if (s_ne7sshInst == NULL)
    {
        s_ne7sshInst = ne7ssh_impl::create();
    }
}

void ne7ssh::destroy()
{
    s_ne7sshInst->destroy();
    s_ne7sshInst.reset();
}

const char* ne7ssh::getVersion(const bool shortVersion)
{
    if (shortVersion == true)
    {
        return NE7SSH_SHORT_VERSION;
    }
    else
    {
        return NE7SSH_FULL_VERSION;
    }
}

int ne7ssh::connectWithPassword(const char* host, const short port, const char* username, const char* password, bool shell, const int timeout)
{
    return s_ne7sshInst->connectWithPassword(host, port, username, password, shell, timeout);
}

int ne7ssh::connectWithKey(const char* host, const short port, const char* username, const char* privKeyFileName, bool shell, const int timeout)
{
    return s_ne7sshInst->connectWithKey(host, port, username, privKeyFileName, shell, timeout);
}

bool ne7ssh::send(const char* data, int channel)
{
    return s_ne7sshInst->send(data, channel);
}

bool ne7ssh::sendCmd(const char* cmd, int channel, int timeout)
{
    return s_ne7sshInst->sendCmd(cmd, channel, timeout);
}

bool ne7ssh::close(int channel)
{
    return s_ne7sshInst->close(channel);
}

const char* ne7ssh::read(int channel)
{
    return s_ne7sshInst->read(channel);
}

void* ne7ssh::readBinary(int channel)
{
    return s_ne7sshInst->readBinary(channel);
}

int ne7ssh::getReceivedSize(int channel)
{
    return s_ne7sshInst->getReceivedSize(channel);
}

bool ne7ssh::waitFor(int channel, const char* str, uint32 timeout)
{
    return s_ne7sshInst->waitFor(channel, str, timeout);
}

void ne7ssh::setOptions(const char* prefCipher, const char* prefHmac)
{
    s_ne7sshInst->setOptions(prefCipher, prefHmac);
}

bool ne7ssh::generateKeyPair(const char* type, const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, uint16 keySize)
{
    return s_ne7sshInst->generateKeyPair(type, fqdn, privKeyFileName, pubKeyFileName, keySize);
}

bool ne7ssh::initSftp(Ne7SftpSubsystem& sftpSubsys, int channel)
{
    return s_ne7sshInst->initSftp(sftpSubsys, channel);
}

Ne7sshError* ne7ssh::errors()
{
    return s_ne7sshInst->errors();
}

Ne7SftpSubsystem::Ne7SftpSubsystem () : _inited(false), _sftp(0)
{
}

Ne7SftpSubsystem::Ne7SftpSubsystem (std::shared_ptr<Ne7sshSftp> sftp)
    : _inited(true),
    _sftp(sftp)
{
}

Ne7SftpSubsystem::~Ne7SftpSubsystem ()
{
}

bool Ne7SftpSubsystem::setTimeout(uint32 _timeout)
{
    if (!_inited)
    {
        return errorNotInited();
    }
    _sftp->setTimeout(_timeout);
    return true;
}

uint32 Ne7SftpSubsystem::openFile(const char* filename, uint8 mode)
{
    if (!_inited)
    {
        return errorNotInited();
    }
    return _sftp->openFile(filename, mode);
}

uint32 Ne7SftpSubsystem::openDir(const char* dirname)
{
    if (!_inited)
    {
        return errorNotInited();
    }
    return _sftp->openDir(dirname);
}

bool Ne7SftpSubsystem::readFile(uint32 fileID, uint64 offset)
{
    if (!_inited)
    {
        return errorNotInited();
    }
    return _sftp->readFile(fileID, offset);
}

bool Ne7SftpSubsystem::writeFile(uint32 fileID, const uint8* data, uint32 len, uint64 offset)
{
    if (!_inited)
    {
        return errorNotInited();
    }
    return _sftp->writeFile(fileID, data, len, offset);
}

bool Ne7SftpSubsystem::closeFile(uint32 fileID)
{
    if (!_inited)
    {
        return errorNotInited();
    }
    return _sftp->closeFile(fileID);
}

bool Ne7SftpSubsystem::errorNotInited()
{
    ne7ssh::errors()->push(-1, "This SFTP system has not been initialized.");
    return false;
}

bool Ne7SftpSubsystem::getFileAttrs(fileAttrs& attrs, const char* filename, bool followSymLinks)
{
    if (!_inited)
    {
        return errorNotInited();
    }
    return _sftp->getFileAttrs(attrs, filename, followSymLinks);
}

bool Ne7SftpSubsystem::get(const char* remoteFile, FILE* localFile)
{
    if (!_inited)
    {
        return errorNotInited();
    }
    return _sftp->get(remoteFile, localFile);
}

bool Ne7SftpSubsystem::put(FILE* localFile, const char* remoteFile)
{
    if (!_inited)
    {
        return errorNotInited();
    }
    return _sftp->put(localFile, remoteFile);
}

bool Ne7SftpSubsystem::rm(const char* remoteFile)
{
    if (!_inited)
    {
        return errorNotInited();
    }
    return _sftp->rm(remoteFile);
}

bool Ne7SftpSubsystem::mv(const char* oldFile, const char* newFile)
{
    if (!_inited)
    {
        return errorNotInited();
    }
    return _sftp->mv(oldFile, newFile);
}

bool Ne7SftpSubsystem::mkdir(const char* remoteDir)
{
    if (!_inited)
    {
        return errorNotInited();
    }
    return _sftp->mkdir(remoteDir);
}

bool Ne7SftpSubsystem::rmdir(const char* remoteDir)
{
    if (!_inited)
    {
        return errorNotInited();
    }
    return _sftp->rmdir(remoteDir);
}

const char* Ne7SftpSubsystem::ls(const char* remoteDir, bool longNames)
{
    if (!_inited)
    {
        errorNotInited();
        return 0;
    }
    return _sftp->ls(remoteDir, longNames);
}

bool Ne7SftpSubsystem::cd(const char* remoteDir)
{
    if (!_inited)
    {
        return errorNotInited();
    }
    return _sftp->cd(remoteDir);
}

bool Ne7SftpSubsystem::chmod(const char* remoteFile, const char* mode)
{
    if (!_inited)
    {
        return errorNotInited();
    }
    return _sftp->chmod(remoteFile, mode);
}

bool Ne7SftpSubsystem::chown(const char* remoteFile, uint32_t uid, uint32_t gid)
{
    if (!_inited)
    {
        return errorNotInited();
    }
    return _sftp->chown(remoteFile, uid, gid);
}

bool Ne7SftpSubsystem::isFile(const char* remoteFile)
{
    if (!_inited)
    {
        return errorNotInited();
    }
    return _sftp->isFile(remoteFile);
}

bool Ne7SftpSubsystem::isDir(const char* remoteFile)
{
    if (!_inited)
    {
        return errorNotInited();
    }
    return _sftp->isDir(remoteFile);
}

