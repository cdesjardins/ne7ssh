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

#ifndef NE7SSH_IMPL_H
#define NE7SSH_IMPL_H

#include <botan/build.h>

#include "ne7ssh_types.h"
#include "ne7ssh_error.h"

#include <stdlib.h>
#include <string>
#include <fcntl.h>
#include <thread>
#include <memory>

#define SSH2_MSG_DISCONNECT 1
#define SSH2_MSG_IGNORE 2

#define SSH2_MSG_KEXINIT  20
#define SSH2_MSG_NEWKEYS  21

#define SSH2_MSG_KEXDH_INIT 30
#define SSH2_MSG_KEXDH_REPLY  31

#define SSH2_MSG_SERVICE_REQUEST 5
#define SSH2_MSG_SERVICE_ACCEPT 6

#define SSH2_MSG_USERAUTH_REQUEST 50
#define SSH2_MSG_USERAUTH_FAILURE 51
#define SSH2_MSG_USERAUTH_SUCCESS 52
#define SSH2_MSG_USERAUTH_BANNER 53
#define SSH2_MSG_USERAUTH_PK_OK 60

#define SSH2_MSG_CHANNEL_OPEN                           90
#define SSH2_MSG_CHANNEL_OPEN_CONFIRMATION              91
#define SSH2_MSG_CHANNEL_OPEN_FAILURE                   92
#define SSH2_MSG_CHANNEL_WINDOW_ADJUST                  93
#define SSH2_MSG_CHANNEL_DATA                           94
#define SSH2_MSG_CHANNEL_EXTENDED_DATA                  95
#define SSH2_MSG_CHANNEL_EOF                            96
#define SSH2_MSG_CHANNEL_CLOSE                          97
#define SSH2_MSG_CHANNEL_REQUEST                        98
#define SSH2_MSG_CHANNEL_SUCCESS                        99
#define SSH2_MSG_CHANNEL_FAILURE                        100

class ne7ssh_connection;

/** definitions for Botan */
namespace Botan
{
    class LibraryInitializer;
}

class Ne7SftpSubsystem;

/**
@author Andrew Useckas
*/
class ne7ssh_impl
{
private:

    static std::recursive_mutex s_mutex;
    std::unique_ptr<Botan::LibraryInitializer> _init;
    std::vector<std::shared_ptr<ne7ssh_connection> > _connections;
    volatile static bool s_running;

    /**
    * Send / Receive thread.
    * <p> For Internal use only
    * @return Usually 0 when thread terminates
    */
    static void selectThread(std::shared_ptr<ne7ssh_impl> _ssh);

    /**
    * Returns the number of active channel.
    * @return Active channel.
    */
    uint32 getChannelNo();
    std::thread _selectThread;

    static Ne7sshError* s_errs;

    /**
    * Default constructor. Used to allocate required memory, as well as initializing cryptographic routines.
    * Becuase this class is a singleton, you cannot copy it or assign it.
    */
    ne7ssh_impl();
    ne7ssh_impl(const ne7ssh_impl&);
    ne7ssh_impl& operator=(const ne7ssh_impl&);

public:
    static const char* SSH_VERSION;
    static const char* KEX_ALGORITHMS;
    static const char* HOSTKEY_ALGORITHMS;
    static const char* MAC_ALGORITHMS;
    static const char* CIPHER_ALGORITHMS;
    static const char* COMPRESSION_ALGORITHMS;
    static std::string PREFERED_CIPHER;
    static std::string PREFERED_MAC;

    static std::shared_ptr<ne7ssh_impl> create();
    void destroy();
    /**
    * Destructor.
    */
    ~ne7ssh_impl();

    /**
    * Connect to remote host using SSH2 protocol, with password authentication.
    * @param host Hostname or IP to connect to.
    * @param port Port to connect to.
    * @param username Username to use in authentication.
    * @param password Password to use in authentication.
    * @param shell Set this to true if you wish to launch the shell on the remote end. By default set to true.
    * @param timeout Timeout for the connection procedure, in seconds.
    * @return Returns newly assigned channel ID, or -1 if connection failed.
    */
    int connectWithPassword(const char* host, const short port, const char* username, const char* password, bool shell = true, const int timeout = 0);

    /**
    * Connect to remote host using SSH2 protocol, with publickey authentication.
    * <p> Reads private key from a file specified, and uses it to authenticate to remote host.
    * Remote side must have public key from the key pair for authentication to succeed.
    * @param host Hostname or IP to connect to.
    * @param port Port to connect to.
    * @param username Username to use in authentication.
    * @param privKeyFileName Full path to file containing private key used in authentication.
    * @param shell Set this to true if you wish to launch the shell on the remote end. By default set to true.
    * @param timeout Timeout for the connection procedure, in seconds.
    * @return Returns newly assigned channel ID, or -1 if connection failed.
    */
    int connectWithKey(const char* host, const short port, const char* username, const char* privKeyFileName, bool shell = true, const int timeout = 0);

    /**
    * Retreives count of current connections
    * <p> For internal use only.
    * @return Returns current count of connections.
    */
    //    uint32 getConCount () { return conCount; }

    /**
    * Sends a command string on specified channel, provided the specified channel has been previously opened through connectWithPassword() function.
    * @param data Pointer to the command string to send to a channel.
    * @param channel Channel to send data on.
    * @return Returns true if the send was successful, otherwise false returned.
    */
    bool send(const char* data, int channel);

    /**
    * Can be used to send a single command and disconnect, similiar behavior to openssh when one appends a command to the end of ssh command.
    * @param cmd Remote command to execute. Can be used to read files on unix with 'cat [filename]'.
    * @param channel Channel to send the command.
    * @param timeout How long to wait before giving up.
    * @return Returns true if the send was successful, otherwise false returned.
    */
    bool sendCmd(const char* cmd, int channel, int timeout);

    /**
    * Closes specified channel.
    * @param channel Channel to close.
    * @return Returns true if closing was successful, otherwise false is returned.
    */
    bool close(int channel);

    /**
    * Reads all data from receiving buffer on specified channel.
    * @param channel Channel to read data on.
    * @return Returns string read from receiver buffer or 0 if buffer is empty.
    */
    const char* read(int channel);

    /**
    * Reads all data from receiving buffer on specified channel. Returns pointer to void. Together with getReceivedSize and sendCmd can be used to read remote files.
    * @param channel Channel to read data on.
    * @return Returns pointer to the start of binary data or 0 if nothing received.
    */
    void* readBinary(int channel);

    /**
    * Returns the size of all data read. Used to read buffer passed 0x0.
    * @param channel Channel number which buffer size to check.
    * @return Return size of the buffer, or 0x0 if receive buffer empty.
    */
    int getReceivedSize(int channel);

    /**
    * Wait until receiving buffer contains a string passed in str, or until the function timeouts as specified in timeout.
    * @param channel Channel to wait on.
    * @param str String to wait for.
    * @param timeout Timeout in seconds.
    * @return Returns true if string specified in str variable has been received, otherwise false returned.
    */
    bool waitFor(int channel, const char* str, uint32 timeout = 0);

    /**
    * Sets prefered cipher and hmac algorithms.
    * <p> This function as to be executed before connection functions, just after initialization of ne7ssh class.
    * @param prefCipher prefered cipher algorithm string representation. Possible cipher algorithms are aes256-cbc, twofish-cbc, twofish256-cbc, blowfish-cbc, 3des-cbc, aes128-cbc, cast128-cbc.
    * @param prefHmac preferede hmac algorithm string representation. Possible hmac algorithms are hmac-md5, hmac-sha1, none.
    */
    void setOptions(const char* prefCipher, const char* prefHmac);

    /**
    * Generate key pair.
    * @param type String specifying key type. Currently "dsa" and "rsa" are supported.
    * @param fqdn User id. Usually an Email. For example "test@netsieben.com"
    * @param privKeyFileName Full path to a file where generated private key should be written.
    * @param pubKeyFileName Full path to a file where generated public key should be written.
    * @param keySize Desired key size in bits. If not specified will default to 2048.
    * @return Return true if keys generated and written to the files. Otherwise false is returned.
    */
    bool generateKeyPair(const char* type, const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, uint16 keySize = 0);

    /**
    * This method is used to initialize a new SFTP subsystem.
    * @param _sftp Reference to SFTP subsystem to be initialized.
    * @param channel Channel ID returned by one of the connect methods.
    * @return True if the new subsystem successfully initialized. False on any error.
    */
    bool initSftp(Ne7SftpSubsystem& sftpSubsys, int channel);

    /**
    * This method returns a pointer to the current Error collection.
    * @return the Error collection
    */
    static Ne7sshError* errors();
};

#endif
