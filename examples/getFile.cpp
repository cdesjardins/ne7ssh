/* An example of ne7ssh library usage. Please change the values in connectWithPassword
function before compiling.

This will work with on a unix/linux server with cat utility.

If you are testing this with later openssh versions, make sure to add this
option to your server's configuration file to enable password authentication:

PasswordAuthentication yes
*/

#include <ne7ssh.h>
#include <iostream>
#include <fstream>
#include <string>

void reportError(const std::string &tag, Ne7sshError* errors)
{
    std::string errmsg;
    do
    {
        errmsg = errors->pop();
        if (errmsg.size() > 0)
        {
            std::cerr << tag << " failed with last error: " << errmsg << std::endl;
        }
    } while (errmsg.size() > 0);
}

int main(int argc, char* argv[])
{
    int channel1;
    int filesize = 0;

    if (argc != 4)
    {
        std::cerr << "Error: Three arguments required: " << argv[0] << " <hostname> <username> <password>" << std::endl;
        return EXIT_FAILURE;
    }

    ne7ssh::create();
    // Set SSH connection options.
    ne7ssh::setOptions("aes256-cbc", "hmac-md5");

    // Initiate connection without starting a remote shell.
    channel1 = ne7ssh::connectWithPassword(argv[1], 22, argv[2], argv[3], 0);
    if (channel1 < 0)
    {
        reportError("Connection", ne7ssh::errors());
        return EXIT_FAILURE;
    }

    // cat the remote file, works only on Unix systems. You may need to sepcifiy full path to cat.
    // Timeout after 100 seconds.

    if (!ne7ssh::sendCmd("cat ~/test.bin", channel1, 100))
    {
        reportError("Command", ne7ssh::errors());
        return EXIT_FAILURE;
    }

    // Determine the size of received file.
    filesize = ne7ssh::getReceivedSize(channel1);

    // Open a local file.
    std::fstream file("./test.bin", std::ios_base::out | std::ios_base::binary);

    // Write binary data from the receive buffer to the opened file.
    file.write((char*)ne7ssh::readBinary(channel1), (size_t)filesize);

    // Close the files.
    file.close();

    return EXIT_SUCCESS;
}

