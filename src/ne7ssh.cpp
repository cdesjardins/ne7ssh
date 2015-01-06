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

#include <signal.h>
#include <time.h>
#include <botan/init.h>
#include <botan/auto_rng.h>
#include "ne7ssh_string.h"
#include "ne7ssh_connection.h"
#include "ne7ssh.h"
#include "ne7ssh_keys.h"

using namespace Botan;
using namespace std;

const char* ne7ssh::SSH_VERSION = "SSH-2.0-NetSieben_1.3.2";
std::shared_ptr<ne7ssh> ne7ssh::s_ne7sshInst;
Ne7sshError* ne7ssh::s_errs = NULL;

std::unique_ptr<RandomNumberGenerator> ne7ssh::s_rng = NULL;

#ifdef _DEMO_BUILD
const char* ne7ssh::MAC_ALGORITHMS = "none";
const char* ne7ssh::CIPHER_ALGORITHMS = "3des-cbc";
const char* ne7ssh::KEX_ALGORITHMS = "diffie-hellman-group1-sha1";
const char* ne7ssh::HOSTKEY_ALGORITHMS = "ssh-dss";
#else
const char* ne7ssh::MAC_ALGORITHMS = "hmac-md5,hmac-sha1,none";
const char* ne7ssh::CIPHER_ALGORITHMS = "aes256-cbc,aes192-cbc,twofish-cbc,twofish256-cbc,blowfish-cbc,3des-cbc,aes128-cbc,cast128-cbc";
const char* ne7ssh::KEX_ALGORITHMS = "diffie-hellman-group1-sha1,diffie-hellman-group14-sha1";
const char* ne7ssh::HOSTKEY_ALGORITHMS = "ssh-dss,ssh-rsa";
#endif

const char* ne7ssh::COMPRESSION_ALGORITHMS = "none";
std::string ne7ssh::PREFERED_CIPHER;
std::string ne7ssh::PREFERED_MAC;
std::recursive_mutex ne7ssh::s_mutex;
volatile bool ne7ssh::s_running = false;

class Locking_AutoSeeded_RNG : public Botan::RandomNumberGenerator
{
public:
    Locking_AutoSeeded_RNG()
        : _rng(new Botan::AutoSeeded_RNG())
    {
    }

    ~Locking_AutoSeeded_RNG()
    {
    }

    void randomize(byte output[], size_t length)
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        _rng->randomize(output, length);
    }

    void clear() throw()
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        _rng->clear();
    }

    std::string name() const
    {
        return _rng->name();
    }

    void reseed(size_t bits_to_collect)
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        _rng->reseed(bits_to_collect);
    }

    void add_entropy_source(EntropySource* source)
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        _rng->add_entropy_source(source);
    }

    void add_entropy(const byte in[], size_t length)
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        _rng->add_entropy(in, length);
    }

private:
    std::recursive_mutex _mutex;
    std::unique_ptr<Botan::RandomNumberGenerator> _rng;
};

std::shared_ptr<ne7ssh> ne7ssh::ne7sshCreate()
{
    if (s_ne7sshInst == NULL)
    {
        s_ne7sshInst.reset(new ne7ssh());
        s_ne7sshInst->_selectThread = std::thread(&ne7ssh::selectThread, s_ne7sshInst);
    }
    return s_ne7sshInst;
}

ne7ssh::ne7ssh()
{
    s_errs = new Ne7sshError();
    _init.reset(new LibraryInitializer("thread_safe"));
    ne7ssh::s_running = true;
    ne7ssh::s_rng.reset(new Locking_AutoSeeded_RNG());
}

ne7ssh::~ne7ssh()
{
    uint32 i;

    ne7ssh::s_running = false;
    try
    {
        std::unique_lock<std::recursive_mutex> lock(s_mutex);
        for (i = 0; i < _connections.size(); i++)
        {
            close(i);
        }
    }
    catch (const std::system_error &ex)
    {
        s_errs->push(-1, "Unable to get lock %s", ex.what());
    }
    _selectThread.join();

    _connections.clear();

    ne7ssh::PREFERED_CIPHER.clear();
    ne7ssh::PREFERED_MAC.clear();
    if (s_errs)
    {
        delete (s_errs);
        s_errs = 0;
    }
    ne7ssh::s_rng.reset();
    _init.reset();
}

void ne7ssh::selectThread(std::shared_ptr<ne7ssh> ssh)
{
    uint32 i;
    int status = 0;
    fd_set rd;
    SOCKET rfds;
    struct timeval waitTime;
    bool cmdOrShell = false;
    bool fdIsSet;

    while (s_running)
    {
        try
        {
            fdIsSet = false;
            rfds = 0;
            std::unique_lock<std::recursive_mutex> lock(s_mutex);
            for (i = 0; i < ssh->_connections.size(); i++)
            {
                if (ssh->_connections[i]->isOpen() && ssh->_connections[i]->data2Send() && !ssh->_connections[i]->isSftpActive())
                {
                    ssh->_connections[i]->sendData();
                }
            }

            waitTime.tv_sec = 0;
            waitTime.tv_usec = 10000;

            FD_ZERO(&rd);

            for (i = 0; i < ssh->_connections.size(); i++)
            {
                cmdOrShell = (ssh->_connections[i]->isRemoteShell() || ssh->_connections[i]->isCmdRunning()) ? true : false;
                if (ssh->_connections[i]->isOpen() && cmdOrShell)
                {
                    rfds = rfds > ssh->_connections[i]->getSocket() ? rfds : ssh->_connections[i]->getSocket();
#if defined(WIN32)
#pragma warning(push)
#pragma warning(disable : 4127)
#endif
                    FD_SET(ssh->_connections[i]->getSocket(), &rd);
#if defined(WIN32)
#pragma warning(pop)
#endif
                    if (!fdIsSet)
                    {
                        fdIsSet = true;
                    }
                }
                else if ((ssh->_connections[i]->isConnected() && ssh->_connections[i]->isRemoteShell()) || ssh->_connections[i]->isCmdClosed())
                {
                    ssh->_connections.erase(ssh->_connections.begin() + i);
                }
            }
        }
        catch (const std::system_error &ex)
        {
            s_errs->push(-1, "Unable to get lock in selectThread %s.", ex.what());
        }

        if (fdIsSet)
        {
            if (rfds)
            {
                status = select(rfds + 1, &rd, NULL, NULL, &waitTime);
            }
            else
            {
                status = select(rfds + 1, NULL, &rd, NULL, &waitTime);
            }
        }
        else
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (status == -1)
        {
            s_errs->push(-1, "Error within select thread.");
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        try
        {
            std::unique_lock<std::recursive_mutex> lock(s_mutex);

            for (i = 0; i < ssh->_connections.size(); i++)
            {
                if (ssh->_connections[i]->isOpen() && FD_ISSET(ssh->_connections[i]->getSocket(), &rd))
                {
                    ssh->_connections[i]->handleData();
                }
            }
        }
        catch (const std::system_error &ex)
        {
            s_errs->push(-1, "Unable to get lock in selectThread %s.", ex.what());
        }
    }
}

int ne7ssh::connectWithPassword(const char* host, const short port, const char* username, const char* password, bool shell, const int timeout)
{
    int channel;
    uint32 currentRecord = 0, z;
    uint32 channelID;

    std::shared_ptr<ne7ssh_connection> con(new ne7ssh_connection());
    try
    {
        std::unique_lock<std::recursive_mutex> lock(s_mutex);
        _connections.push_back(con);
        channelID = getChannelNo();
        con->setChannelNo(channelID);
    }
    catch (const std::system_error &ex)
    {
        s_errs->push(-1, "Unable to get lock in connectWithPassword %s.", ex.what());
        return -1;
    }

    channel = con->connectWithPassword(channelID, host, port, username, password, shell, timeout);

    if (channel == -1)
    {
        try
        {
            std::unique_lock<std::recursive_mutex> lock(s_mutex);
            for (z = 0; z < _connections.size(); z++)
            {
                if (_connections[z] == con)
                {
                    currentRecord = z;
                    break;
                }
            }
            if (z == _connections.size())
            {
                ne7ssh::errors()->push(-1, "Unexpected behaviour!");
                return -1;
            }
            _connections.erase(_connections.begin() + currentRecord);
        }
        catch (const std::system_error &ex)
        {
            s_errs->push(-1, "Unable to get lock in connectWithPassword %s.", ex.what());
            return -1;
        }
    }
    return channel;
}

int ne7ssh::connectWithKey(const char* host, const short port, const char* username, const char* privKeyFileName, bool shell, const int timeout)
{
    int channel;
    uint32 currentRecord = 0, z;
    uint32 channelID;

    std::shared_ptr<ne7ssh_connection> con(new ne7ssh_connection());
    try
    {
        std::unique_lock<std::recursive_mutex> lock(s_mutex);
        _connections.push_back(con);
        channelID = getChannelNo();
        con->setChannelNo(channelID);
    }
    catch (const std::system_error &ex)
    {
        s_errs->push(-1, "Unable to get lock in connectWithKey %s.", ex.what());
        return -1;
    }

    channel = con->connectWithKey(channelID, host, port, username, privKeyFileName, shell, timeout);

    if (channel == -1)
    {
        try
        {
            std::unique_lock<std::recursive_mutex> lock(s_mutex);
            for (z = 0; z < _connections.size(); z++)
            {
                if (_connections[z] == con)
                {
                    currentRecord = z;
                    break;
                }
            }
            if (z == _connections.size())
            {
                ne7ssh::errors()->push(-1, "Unexpected behaviour!");
                return -1;
            }
            _connections.erase(_connections.begin() + currentRecord);
        }
        catch (const std::system_error &ex)
        {
            s_errs->push(-1, "Unable to get lock in connectWithKey %s.", ex.what());
            return -1;
        }
    }
    return channel;
}

bool ne7ssh::send(const char* data, int channel)
{
    uint32 i;
    try
    {
        std::unique_lock<std::recursive_mutex> lock(s_mutex);
        for (i = 0; i < _connections.size(); i++)
        {
            if (channel == _connections[i]->getChannelNo())
            {
                _connections[i]->sendData(data);
                return true;
            }
        }
    }
    catch (const std::system_error &ex)
    {
        s_errs->push(-1, "Unable to get lock %s", ex.what());
        return false;
    }
    s_errs->push(-1, "Bad channel: %i specified for sending.", channel);
    return false;
}

bool ne7ssh::initSftp(Ne7SftpSubsystem& sftpSubsys, int channel)
{
    uint32 i;
    std::shared_ptr<Ne7sshSftp> sftp;

    try
    {
        std::unique_lock<std::recursive_mutex> lock(s_mutex);
        for (i = 0; i < _connections.size(); i++)
        {
            if (channel == _connections[i]->getChannelNo())
            {
                sftp = _connections[i]->startSftp();
                if (!sftp)
                {
                    return false;
                }
                else
                {
                    Ne7SftpSubsystem sftpSubsystem(sftp);
                    sftpSubsys = sftpSubsystem;
                    return true;
                }
            }
        }
    }
    catch (const std::system_error &ex)
    {
        s_errs->push(-1, "Unable to get lock %s", ex.what());
        return false;
    }

    s_errs->push(-1, "Bad channel: %i specified. Cannot initialize SFTP subsystem.", channel);
    return false;
}

bool ne7ssh::sendCmd(const char* cmd, int channel, int timeout)
{
    uint32 i;
    time_t cutoff = 0;
    bool status;

    if (timeout)
    {
        cutoff = time(NULL) + timeout;
    }
    try
    {
        std::unique_lock<std::recursive_mutex> lock(s_mutex);
        for (i = 0; i < _connections.size(); i++)
        {
            if (channel == _connections[i]->getChannelNo())
            {
                status = _connections[i]->sendCmd(cmd);
                if (!status)
                {
                    return false;
                }

                if (!timeout)
                {
                    while (!_connections[i]->getCmdComplete())
                    {
                        for (i = 0; i < _connections.size(); i++)
                        {
                            if (channel == _connections[i]->getChannelNo())
                            {
                                break;
                            }
                        }
                        if (i == _connections.size())
                        {
                            s_errs->push(-1, "Bad channel: %i specified for sending.", channel);
                            return false;
                        }
                        if (!_connections[i]->getCmdComplete())
                        {
                            s_mutex.unlock();
                            std::this_thread::sleep_for(std::chrono::milliseconds(1));
                            s_mutex.lock();
                        }
                    }
                }
                else if (timeout > 0)
                {
                    while (!_connections[i]->getCmdComplete())
                    {
                        for (i = 0; i < _connections.size(); i++)
                        {
                            if (channel == _connections[i]->getChannelNo())
                            {
                                break;
                            }
                        }
                        if (i == _connections.size())
                        {
                            s_errs->push(-1, "Bad channel: %i specified for sending.", channel);
                            return false;
                        }
                        if (!_connections[i]->getCmdComplete())
                        {
                            s_mutex.unlock();
                            std::this_thread::sleep_for(std::chrono::milliseconds(1));
                            s_mutex.lock();
                            if (!cutoff)
                            {
                                continue;
                            }
                            if (time(NULL) >= cutoff)
                            {
                                break;
                            }
                        }
                    }
                }
                return true;
            }
        }
    }
    catch (const std::system_error &ex)
    {
        s_errs->push(-1, "Unable to get lock %s", ex.what());
        return false;
    }
    s_errs->push(-1, "Bad channel: %i specified for sending.", channel);
    return false;
}

bool ne7ssh::close(int channel)
{
    uint32 i;
    bool status = false;

    if (channel == -1)
    {
        s_errs->push(-1, "Bad channel: %i specified for closing.", channel);
        return false;
    }
    try
    {
        std::unique_lock<std::recursive_mutex> lock(s_mutex);
        for (i = 0; i < _connections.size(); i++)
        {
            if (channel == _connections[i]->getChannelNo())
            {
                status = _connections[i]->sendClose();
            }
        }
        s_errs->deleteChannel(channel);
    }
    catch (const std::system_error &ex)
    {
        s_errs->push(-1, "Unable to get lock %s", ex.what());
        return false;
    }

    return status;
}

bool ne7ssh::waitFor(int channel, const char* str, uint32 timeSec)
{
    Botan::byte one;
    const Botan::byte* carret;
    const char* buffer;
    size_t len = 0, carretLen = 0, str_len = 0, prevLen = 0;
    time_t cutoff = 0;
    bool forever = true;

    if (timeSec)
    {
        cutoff = time(NULL) + timeSec;
    }

    if (channel == -1)
    {
        s_errs->push(-1, "Bad channel: %i specified for waiting.", channel);
        return false;
    }

    str_len = strlen(str);

    while (forever)
    {
        try
        {
            std::unique_lock<std::recursive_mutex> lock(s_mutex);
            buffer = read(channel);
            if (buffer)
            {
                len = getReceivedSize(channel);
                if (!(cutoff && prevLen && len == prevLen))
                {
                    prevLen = len;
                }
                carret = (const Botan::byte*) buffer + len - 1;
                one = *str;
                carretLen = 1;

                while (carretLen <= len)
                {
                    if ((*carret == one) && (str_len <= carretLen))
                    {
                        if (!memcmp(carret, str, str_len))
                        {
                            return true;
                        }
                    }
                    carretLen++;
                    carret--;
                }
            }
        }
        catch (const std::system_error &ex)
        {
            s_errs->push(-1, "Unable to get lock %s", ex.what());
            return false;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        if (!cutoff)
        {
            continue;
        }
        if (time(NULL) >= cutoff)
        {
            break;
        }
    }
    return false;
}

const char* ne7ssh::read(int channel)
{
    uint32 i;
    SecureVector<Botan::byte> data;

    if (channel == -1)
    {
        s_errs->push(-1, "Bad channel: %i specified for reading.", channel);
        return NULL;
    }
    try
    {
        std::unique_lock<std::recursive_mutex> lock(s_mutex);
        for (i = 0; i < _connections.size(); i++)
        {
            if (channel == _connections[i]->getChannelNo())
            {
                data = _connections[i]->getReceived();
                if (data.size())
                {
                    return ((const char*)_connections[i]->getReceived().begin());
                }
            }
        }
    }
    catch (const std::system_error &ex)
    {
        s_errs->push(-1, "Unable to get lock %s", ex.what());
        return NULL;
    }

    return NULL;
}

void* ne7ssh::readBinary(int channel)
{
    uint32 i;
    SecureVector<Botan::byte> data;

    if (channel == -1)
    {
        s_errs->push(-1, "Bad channel: %i specified for reading.", channel);
        return NULL;
    }
    try
    {
        std::unique_lock<std::recursive_mutex> lock(s_mutex, std::defer_lock);
        for (i = 0; i < _connections.size(); i++)
        {
            if (channel == _connections[i]->getChannelNo())
            {
                data = _connections[i]->getReceived();
                if (data.size())
                {
                    return ((void*)_connections[i]->getReceived().begin());
                }
            }
        }
    }
    catch (const std::system_error &ex)
    {
        s_errs->push(-1, "Unable to get lock %s", ex.what());
        return NULL;
    }

    return NULL;
}

int ne7ssh::getReceivedSize(int channel)
{
    uint32 i;
    int size;
    try
    {
        std::unique_lock<std::recursive_mutex> lock(s_mutex);

        for (i = 0; i < _connections.size(); i++)
        {
            if (channel == _connections[i]->getChannelNo())
            {
                if (!_connections[i]->getReceived().size())
                {
                    return 0;
                }
                else
                {
                    size = _connections[i]->getReceived().size();
                    return (size);
                }
            }
        }
    }
    catch (const std::system_error &ex)
    {
        s_errs->push(-1, "Unable to get lock %s", ex.what());
        return false;
    }

    return 0;
}

uint32 ne7ssh::getChannelNo()
{
    uint32 i;
    int32 channelID = 1;

    if (_connections.size() == 0)
    {
        return channelID;
    }

    for (channelID = 1; channelID != 0x7FFFFFFF; channelID++)
    {
        for (i = 0; i < _connections.size(); i++)
        {
            if (_connections[i] && (_connections[i]->getChannelNo() == channelID))
            {
                break;
            }
        }
        if (i == _connections.size())
        {
            break;
        }
    }

    if (channelID == 0x7FFFFFFF)
    {
        s_errs->push(-1, "Maximum theoretical channel count reached!");
        return 0;
    }
    else
    {
        return channelID;
    }
}

void ne7ssh::setOptions(const char* prefCipher, const char* prefHmac)
{
    if (prefCipher)
    {
        ne7ssh::PREFERED_CIPHER.assign(prefCipher);
    }

    if (prefHmac)
    {
        ne7ssh::PREFERED_MAC.assign(prefHmac);
    }
}

SSH_EXPORT Ne7sshError* ne7ssh::errors()
{
    return s_errs;
}

bool ne7ssh::generateKeyPair(const char* type, const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, uint16 keySize)
{
    ne7ssh_keys keyPair;
    enum keyAlgos { UNKNOWN, DSA, RSA };
    uint8 keyAlgo = UNKNOWN;

    if (!memcmp(type, "dsa", 3))
    {
        keyAlgo = DSA;
    }
    else if (!memcmp(type, "rsa", 3))
    {
        keyAlgo = RSA;
    }

    switch (keyAlgo)
    {
        case DSA:
            if (!keySize)
            {
                return keyPair.generateDSAKeys(fqdn, privKeyFileName, pubKeyFileName);
            }
            else
            {
                return keyPair.generateDSAKeys(fqdn, privKeyFileName, pubKeyFileName, keySize);
            }

        case RSA:
            if (!keySize)
            {
                return keyPair.generateRSAKeys(fqdn, privKeyFileName, pubKeyFileName);
            }
            else
            {
                return keyPair.generateRSAKeys(fqdn, privKeyFileName, pubKeyFileName, keySize);
            }

        default:
            s_errs->push(-1, "The specfied key algorithm: %i not supported", keyAlgo);
    }
    return false;
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

