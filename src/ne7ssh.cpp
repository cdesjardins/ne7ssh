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
Ne7sshError* ne7ssh::errs = NULL;

#if !BOTAN_PRE_18 && !BOTAN_PRE_15
RandomNumberGenerator* ne7ssh::rng = NULL;
#endif

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
char* ne7ssh::PREFERED_CIPHER = 0;
char* ne7ssh::PREFERED_MAC = 0;
std::recursive_mutex ne7ssh::_mutex;
volatile bool ne7ssh::running = false;
bool ne7ssh::selectActive = true;

class Locking_AutoSeeded_RNG : public Botan::RandomNumberGenerator
{
public:
    Locking_AutoSeeded_RNG()
    {
        rng = new Botan::AutoSeeded_RNG();
    }

    ~Locking_AutoSeeded_RNG()
    {
        delete rng;
    }

    void randomize(byte output[], size_t length)
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        rng->randomize(output, length);
    }

    void clear() throw()
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        rng->clear();
    }

    std::string name() const
    {
        return rng->name();
    }

    void reseed(size_t bits_to_collect)
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        rng->reseed(bits_to_collect);
    }

    void add_entropy_source(EntropySource* source)
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        rng->add_entropy_source(source);
    }

    void add_entropy(const byte in[], size_t length)
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        rng->add_entropy(in, length);
    }

private:
    std::recursive_mutex _mutex;
    Botan::RandomNumberGenerator* rng;
};

ne7ssh::ne7ssh() : connections(0), conCount(0)
{
    errs = new Ne7sshError();
    if (ne7ssh::running)
    {
        errs->push(-1, "Cannot initialize more than more instance of ne7ssh class within the same application. Aborting.");
        // FIXME: throw exception
        return;
    }
    init = new LibraryInitializer("thread_safe");
    ne7ssh::running = true;
    allConns.conns = 0;
    allConns.count = 0;

#if !BOTAN_PRE_18 && !BOTAN_PRE_15
    ne7ssh::rng = new Locking_AutoSeeded_RNG();
#endif

    // FIXME: Dont start threads in constructors...
    // and handle exceptions
    _selectThread = std::thread(&ne7ssh::selectThread, this);
}

ne7ssh::~ne7ssh()
{
    uint32 i;

    ne7ssh::running = false;
    try
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        for (i = 0; i < conCount; i++)
        {
            close(i);
        }
    }
    catch (const std::system_error &ex)
    {
        errs->push(-1, "Unable to get lock %s", ex.what());
    }
    _selectThread.join();

    if (conCount)
    {
        for (i = 0; i < conCount; i++)
        {
            delete connections[i];
        }
        free(connections);
    }
    else if (connections)
    {
        free(connections);
    }

    if (ne7ssh::PREFERED_CIPHER)
    {
        free(ne7ssh::PREFERED_CIPHER);
        ne7ssh::PREFERED_CIPHER = 0;
    }
    if (ne7ssh::PREFERED_MAC)
    {
        free(ne7ssh::PREFERED_MAC);
        ne7ssh::PREFERED_MAC = 0;
    }
    if (errs)
    {
        delete (errs);
        errs = 0;
    }
#if !BOTAN_PRE_18 && !BOTAN_PRE_15
    if (ne7ssh::rng)
    {
        delete (rng);
        rng = 0;
    }
#endif

    delete init;
}

void* ne7ssh::selectThread(void* initData)
{
    ne7ssh* _ssh = (ne7ssh*) initData;
    uint32 i, z;
    int status = 0;
    fd_set rd;
    SOCKET rfds;
    struct timeval waitTime;
    connStruct* allConns;
    bool cmdOrShell = false;
    bool fdIsSet;

    while (running)
    {
        try
        {
            fdIsSet = false;
            rfds = 0;
            std::unique_lock<std::recursive_mutex> lock(_mutex);
            allConns = _ssh->getConnetions();
            for (i = 0; i < allConns->count; i++)
            {
                if (allConns->conns[i]->isOpen() && allConns->conns[i]->data2Send() && !allConns->conns[i]->isSftpActive())
                {
                    allConns->conns[i]->sendData();
                }
            }

            waitTime.tv_sec = 0;
            waitTime.tv_usec = 10000;

            FD_ZERO(&rd);

            for (i = 0; i < allConns->count; i++)
            {
                cmdOrShell = (allConns->conns[i]->isRemoteShell() || allConns->conns[i]->isCmdRunning()) ? true : false;
                if (allConns->conns[i]->isOpen() && cmdOrShell)
                {
                    rfds = rfds > allConns->conns[i]->getSocket() ? rfds : allConns->conns[i]->getSocket();
#if defined(WIN32)
#pragma warning(push)
#pragma warning(disable : 4127)
#endif
                    FD_SET(allConns->conns[i]->getSocket(), &rd);
#if defined(WIN32)
#pragma warning(pop)
#endif
                    if (!fdIsSet)
                    {
                        fdIsSet = true;
                    }
                }
                else if ((allConns->conns[i]->isConnected() && allConns->conns[i]->isRemoteShell()) || allConns->conns[i]->isCmdClosed())
                {
                    delete (allConns->conns[i]);
                    allConns->conns[i] = 0;
                    allConns->count--;
                    for (z = i; z < allConns->count; z++)
                    {
                        allConns->conns[z] = allConns->conns[z + 1];
                        allConns->conns[z + 1] = 0;
                    }
                    _ssh->setCount(allConns->count);
                    i--;
                }
            }
        }
        catch (const std::system_error &ex)
        {
            errs->push(-1, "Unable to get lock in selectThread %s.", ex.what());
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
            errs->push(-1, "Error within select thread.");
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        try
        {
            std::unique_lock<std::recursive_mutex> lock(_mutex);

            allConns = _ssh->getConnetions();
            for (i = 0; i < allConns->count; i++)
            {
                if (allConns->conns[i]->isOpen() && FD_ISSET(allConns->conns[i]->getSocket(), &rd))
                {
                    allConns->conns[i]->handleData();
                }
            }
        }
        catch (const std::system_error &ex)
        {
            errs->push(-1, "Unable to get lock in selectThread %s.", ex.what());
        }
    }
    return 0;
}

int ne7ssh::connectWithPassword(const char* host, const short port, const char* username, const char* password, bool shell, const int timeout)
{
    int channel;
    uint32 currentRecord = 0, z;
    uint32 channelID;

    ne7ssh_connection* con = new ne7ssh_connection();
    try
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        if (!conCount)
        {
            connections = (ne7ssh_connection**) malloc(sizeof (ne7ssh_connection*));
        }
        else
        {
            connections = (ne7ssh_connection**) realloc(connections, sizeof (ne7ssh_connection*) * (conCount + 1));
        }
        connections[conCount++] = con;
        allConns.count = conCount;
        allConns.conns = connections;
        channelID = getChannelNo();
        con->setChannelNo(channelID);
    }
    catch (const std::system_error &ex)
    {
        errs->push(-1, "Unable to get lock in connectWithPassword %s.", ex.what());
        return -1;
    }

    channel = con->connectWithPassword(channelID, host, port, username, password, shell, timeout);

    if (channel == -1)
    {
        try
        {
            std::unique_lock<std::recursive_mutex> lock(_mutex);
            for (z = 0; z < allConns.count; z++)
            {
                if (allConns.conns[z] == con)
                {
                    currentRecord = z;
                    break;
                }
            }
            if (z == allConns.count)
            {
                ne7ssh::errors()->push(-1, "Unexpected behaviour!");
                return -1;
            }

            delete con;
            allConns.conns[currentRecord] = 0;
            allConns.count--;
            for (z = currentRecord; z < allConns.count; z++)
            {
                allConns.conns[z] = allConns.conns[z + 1];
                allConns.conns[z + 1] = 0;
            }
            conCount = allConns.count;
        }
        catch (const std::system_error &ex)
        {
            errs->push(-1, "Unable to get lock in connectWithPassword %s.", ex.what());
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

    ne7ssh_connection* con = new ne7ssh_connection();
    try
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        if (!conCount)
        {
            connections = (ne7ssh_connection**) malloc(sizeof (ne7ssh_connection*) * (conCount + 1));
        }
        else
        {
            connections = (ne7ssh_connection**) realloc(connections, sizeof (ne7ssh_connection*) * (conCount + 1));
        }
        connections[conCount++] = con;
        allConns.count = conCount;
        allConns.conns = connections;
        channelID = getChannelNo();
        con->setChannelNo(channelID);
    }
    catch (const std::system_error &ex)
    {
        errs->push(-1, "Unable to get lock in connectWithKey %s.", ex.what());
        return -1;
    }

    channel = con->connectWithKey(channelID, host, port, username, privKeyFileName, shell, timeout);

    if (channel == -1)
    {
        try
        {
            std::unique_lock<std::recursive_mutex> lock(_mutex);
            for (z = 0; z < allConns.count; z++)
            {
                if (allConns.conns[z] == con)
                {
                    currentRecord = z;
                    break;
                }
            }
            if (z == allConns.count)
            {
                ne7ssh::errors()->push(-1, "Unexpected behaviour!");
                return -1;
            }

            delete con;
            allConns.conns[currentRecord] = 0;
            allConns.count--;
            for (z = currentRecord; z < allConns.count; z++)
            {
                allConns.conns[z] = allConns.conns[z + 1];
                allConns.conns[z + 1] = 0;
            }
            conCount = allConns.count;
        }
        catch (const std::system_error &ex)
        {
            errs->push(-1, "Unable to get lock in connectWithKey %s.", ex.what());
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
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        for (i = 0; i < conCount; i++)
        {
            if (channel == connections[i]->getChannelNo())
            {
                connections[i]->sendData(data);
                return true;
            }
        }
    }
    catch (const std::system_error &ex)
    {
        errs->push(-1, "Unable to get lock %s", ex.what());
        return false;
    }
    errs->push(-1, "Bad channel: %i specified for sending.", channel);
    return false;
}

bool ne7ssh::initSftp(Ne7SftpSubsystem& _sftp, int channel)
{
    uint32 i;
    Ne7sshSftp* __sftp;

    try
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        for (i = 0; i < conCount; i++)
        {
            if (channel == connections[i]->getChannelNo())
            {
                __sftp = connections[i]->startSftp();
                if (!__sftp)
                {
                    return false;
                }
                else
                {
                    Ne7SftpSubsystem sftpSubsystem(__sftp);
                    _sftp = sftpSubsystem;
                    return true;
                }
            }
        }
    }
    catch (const std::system_error &ex)
    {
        errs->push(-1, "Unable to get lock %s", ex.what());
        return false;
    }

    errs->push(-1, "Bad channel: %i specified. Cannot initialize SFTP subsystem.", channel);
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
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        for (i = 0; i < conCount; i++)
        {
            if (channel == connections[i]->getChannelNo())
            {
                status = connections[i]->sendCmd(cmd);
                if (!status)
                {
                    return false;
                }

                if (!timeout)
                {
                    while (!connections[i]->getCmdComplete())
                    {
                        for (i = 0; i < conCount; i++)
                        {
                            if (channel == connections[i]->getChannelNo())
                            {
                                break;
                            }
                        }
                        if (i == conCount)
                        {
                            errs->push(-1, "Bad channel: %i specified for sending.", channel);
                            return false;
                        }
                        if (!connections[i]->getCmdComplete())
                        {
                            _mutex.unlock();
                            std::this_thread::sleep_for(std::chrono::milliseconds(1));
                            _mutex.lock();
                        }
                    }
                }
                else if (timeout > 0)
                {
                    while (!connections[i]->getCmdComplete())
                    {
                        for (i = 0; i < conCount; i++)
                        {
                            if (channel == connections[i]->getChannelNo())
                            {
                                break;
                            }
                        }
                        if (i == conCount)
                        {
                            errs->push(-1, "Bad channel: %i specified for sending.", channel);
                            return false;
                        }
                        if (!connections[i]->getCmdComplete())
                        {
                            _mutex.unlock();
                            std::this_thread::sleep_for(std::chrono::milliseconds(1));
                            _mutex.lock();
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
        errs->push(-1, "Unable to get lock %s", ex.what());
        return false;
    }
    errs->push(-1, "Bad channel: %i specified for sending.", channel);
    return false;
}

bool ne7ssh::close(int channel)
{
    uint32 i;
    bool status = false;

    if (channel == -1)
    {
        errs->push(-1, "Bad channel: %i specified for closing.", channel);
        return false;
    }
    try
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        for (i = 0; i < conCount; i++)
        {
            if (channel == connections[i]->getChannelNo())
            {
                status = connections[i]->sendClose();
            }
        }
        errs->deleteChannel(channel);
    }
    catch (const std::system_error &ex)
    {
        errs->push(-1, "Unable to get lock %s", ex.what());
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
        errs->push(-1, "Bad channel: %i specified for waiting.", channel);
        return false;
    }

    str_len = strlen(str);

    while (forever)
    {
        try
        {
            std::unique_lock<std::recursive_mutex> lock(_mutex);
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
            errs->push(-1, "Unable to get lock %s", ex.what());
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
        errs->push(-1, "Bad channel: %i specified for reading.", channel);
        return NULL;
    }
    try
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        for (i = 0; i < conCount; i++)
        {
            if (channel == connections[i]->getChannelNo())
            {
                data = connections[i]->getReceived();
                if (data.size())
                {
                    return ((const char*)connections[i]->getReceived().begin());
                }
            }
        }
    }
    catch (const std::system_error &ex)
    {
        errs->push(-1, "Unable to get lock %s", ex.what());
        return false;
    }

    return NULL;
}

void* ne7ssh::readBinary(int channel)
{
    uint32 i;
    SecureVector<Botan::byte> data;

    if (channel == -1)
    {
        errs->push(-1, "Bad channel: %i specified for reading.", channel);
        return NULL;
    }
    try
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex, std::defer_lock);
        for (i = 0; i < conCount; i++)
        {
            if (channel == connections[i]->getChannelNo())
            {
                data = connections[i]->getReceived();
                if (data.size())
                {
                    return ((void*)connections[i]->getReceived().begin());
                }
            }
        }
    }
    catch (const std::system_error &ex)
    {
        errs->push(-1, "Unable to get lock %s", ex.what());
        return false;
    }

    return NULL;
}

int ne7ssh::getReceivedSize(int channel)
{
    uint32 i;
    int size;
    try
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);

        for (i = 0; i < conCount; i++)
        {
            if (channel == connections[i]->getChannelNo())
            {
                if (!connections[i]->getReceived().size())
                {
                    return 0;
                }
                else
                {
                    size = connections[i]->getReceived().size();
                    return (size);
                }
            }
        }
    }
    catch (const std::system_error &ex)
    {
        errs->push(-1, "Unable to get lock %s", ex.what());
        return false;
    }

    return 0;
}

uint32 ne7ssh::getChannelNo()
{
    uint32 i;
    int32 channelID = 1;

    if (!conCount)
    {
        return channelID;
    }

    for (channelID = 1; channelID != 0x7FFFFFFF; channelID++)
    {
        for (i = 0; i < conCount; i++)
        {
            if (connections[i] && (connections[i]->getChannelNo() == channelID))
            {
                break;
            }
        }
        if (i == conCount)
        {
            break;
        }
    }

    if (channelID == 0x7FFFFFFF)
    {
        errs->push(-1, "Maximum theoretical channel count reached!");
        return 0;
    }
    else
    {
        return channelID;
    }
}

void ne7ssh::setOptions(const char* prefCipher, const char* prefHmac)
{
    size_t len = 0;

    if (prefCipher)
    {
        len = strlen(prefCipher);
    }
    if (!ne7ssh::PREFERED_CIPHER && len)
    {
        ne7ssh::PREFERED_CIPHER = (char*) malloc(len);
    }
    else if (len)
    {
        ne7ssh::PREFERED_CIPHER = (char*) realloc(ne7ssh::PREFERED_CIPHER, len);
    }
    memcpy(ne7ssh::PREFERED_CIPHER, prefCipher, len);

    len = 0;
    if (prefHmac)
    {
        len = strlen(prefHmac);
    }
    if (!ne7ssh::PREFERED_MAC && len)
    {
        ne7ssh::PREFERED_MAC = (char*) malloc(len);
    }
    else if (len)
    {
        ne7ssh::PREFERED_MAC = (char*) realloc(ne7ssh::PREFERED_MAC, len);
    }
    memcpy(ne7ssh::PREFERED_MAC, prefHmac, len);
}

SSH_EXPORT Ne7sshError* ne7ssh::errors()
{
    return errs;
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
            errs->push(-1, "The specfied key algorithm: %i not supported", keyAlgo);
    }
    return false;
}

Ne7SftpSubsystem::Ne7SftpSubsystem () : inited(false), sftp(0)
{
}

Ne7SftpSubsystem::Ne7SftpSubsystem (Ne7sshSftp* _sftp) : inited(true), sftp((Ne7sshSftp*)_sftp)
{
}

Ne7SftpSubsystem::~Ne7SftpSubsystem ()
{
}

bool Ne7SftpSubsystem::setTimeout(uint32 _timeout)
{
    if (!inited)
    {
        return errorNotInited();
    }
    sftp->setTimeout(_timeout);
    return true;
}

uint32 Ne7SftpSubsystem::openFile(const char* filename, uint8 mode)
{
    if (!inited)
    {
        return errorNotInited();
    }
    return sftp->openFile(filename, mode);
}

uint32 Ne7SftpSubsystem::openDir(const char* dirname)
{
    if (!inited)
    {
        return errorNotInited();
    }
    return sftp->openDir(dirname);
}

bool Ne7SftpSubsystem::readFile(uint32 fileID, uint64 offset)
{
    if (!inited)
    {
        return errorNotInited();
    }
    return sftp->readFile(fileID, offset);
}

bool Ne7SftpSubsystem::writeFile(uint32 fileID, const uint8* data, uint32 len, uint64 offset)
{
    if (!inited)
    {
        return errorNotInited();
    }
    return sftp->writeFile(fileID, data, len, offset);
}

bool Ne7SftpSubsystem::closeFile(uint32 fileID)
{
    if (!inited)
    {
        return errorNotInited();
    }
    return sftp->closeFile(fileID);
}

bool Ne7SftpSubsystem::errorNotInited()
{
    ne7ssh::errors()->push(-1, "This SFTP system has not been initialized.");
    return false;
}

bool Ne7SftpSubsystem::getFileAttrs(fileAttrs& attrs, const char* filename, bool followSymLinks)
{
    if (!inited)
    {
        return errorNotInited();
    }
    return sftp->getFileAttrs(attrs, filename, followSymLinks);
}

bool Ne7SftpSubsystem::get(const char* remoteFile, FILE* localFile)
{
    if (!inited)
    {
        return errorNotInited();
    }
    return sftp->get(remoteFile, localFile);
}

bool Ne7SftpSubsystem::put(FILE* localFile, const char* remoteFile)
{
    if (!inited)
    {
        return errorNotInited();
    }
    return sftp->put(localFile, remoteFile);
}

bool Ne7SftpSubsystem::rm(const char* remoteFile)
{
    if (!inited)
    {
        return errorNotInited();
    }
    return sftp->rm(remoteFile);
}

bool Ne7SftpSubsystem::mv(const char* oldFile, const char* newFile)
{
    if (!inited)
    {
        return errorNotInited();
    }
    return sftp->mv(oldFile, newFile);
}

bool Ne7SftpSubsystem::mkdir(const char* remoteDir)
{
    if (!inited)
    {
        return errorNotInited();
    }
    return sftp->mkdir(remoteDir);
}

bool Ne7SftpSubsystem::rmdir(const char* remoteDir)
{
    if (!inited)
    {
        return errorNotInited();
    }
    return sftp->rmdir(remoteDir);
}

const char* Ne7SftpSubsystem::ls(const char* remoteDir, bool longNames)
{
    if (!inited)
    {
        errorNotInited();
        return 0;
    }
    return sftp->ls(remoteDir, longNames);
}

bool Ne7SftpSubsystem::cd(const char* remoteDir)
{
    if (!inited)
    {
        return errorNotInited();
    }
    return sftp->cd(remoteDir);
}

bool Ne7SftpSubsystem::chmod(const char* remoteFile, const char* mode)
{
    if (!inited)
    {
        return errorNotInited();
    }
    return sftp->chmod(remoteFile, mode);
}

bool Ne7SftpSubsystem::chown(const char* remoteFile, uint32_t uid, uint32_t gid)
{
    if (!inited)
    {
        return errorNotInited();
    }
    return sftp->chown(remoteFile, uid, gid);
}

bool Ne7SftpSubsystem::isFile(const char* remoteFile)
{
    if (!inited)
    {
        return errorNotInited();
    }
    return sftp->isFile(remoteFile);
}

bool Ne7SftpSubsystem::isDir(const char* remoteFile)
{
    if (!inited)
    {
        return errorNotInited();
    }
    return sftp->isDir(remoteFile);
}

