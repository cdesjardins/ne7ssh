/* An example of ne7ssh library usage. Please change the values in connectWithPassword
   function before compiling.

   This will work with openssh server if default shell of authenticating user is bash.
   When using a different shell or custom prompt replace " $" string in waitFor()
   method with a string corresponding with your shell prompt.

   If you are testing this with later openssh versions, make sure to add this
   option to your server's configuration file to enable password authentication:

   PasswordAuthentication yes
*/

#include <ne7ssh.h>
#include <iostream>

void reportError(const std::string &tag, ne7ssh* ssh)
{
    std::string errmsg;
    do
    {
        errmsg = ssh->errors()->pop();
        if (errmsg.size() > 0)
        {
            std::cerr << tag << " failed with last error: " << errmsg << std::endl;
        }
    } while (errmsg.size() > 0);
}

int main(int argc, char* argv[])
{
    int channel1;
    const char* result;

    if (argc != 4)
    {
        std::cerr << "Error: Three arguments required: " << argv[0] << " <hostname> <username> <password>" << std::endl;
        return EXIT_FAILURE;
    }

    ne7ssh* _ssh = new ne7ssh();

    // Set SSH connection options.
    _ssh->setOptions("aes192-cbc", "hmac-md5");

    // Initiate connection.
    channel1 = _ssh->connectWithPassword(argv[1], 22, argv[2], argv[3]);
    if (channel1 < 0)
    {
        reportError("Connection", _ssh);
        delete _ssh;
        return EXIT_FAILURE;
    }

    // Wait for bash prompt, or die in 5 seconds.
    if (!_ssh->waitFor(channel1, " $", 5))
    {
        reportError("Wait", _ssh);
        _ssh->close(channel1);
        delete _ssh;
        return EXIT_FAILURE;
    }

    // Send "ps ax" command.
    if (!_ssh->send("ps ax\n", channel1))
    {
        reportError("ps", _ssh);
        _ssh->close(channel1);
        delete _ssh;
        return EXIT_FAILURE;
    }

    // Wait for bash prompt, or die in 5 seconds
    if (!_ssh->waitFor(channel1, " $", 5))
    {
        reportError("Wait for ps", _ssh);
        _ssh->close(channel1);
        delete _ssh;
        return EXIT_FAILURE;
    }

    // Fetch recieved data.
    result = _ssh->read(channel1);

    if (!result)
    {
        reportError("Data received", _ssh);
    }
    else
    {
        std::cout << "Received data:" << std::endl << result << std::endl;
    }

    // Send "netstat -na" command.
    if (!_ssh->send("netstat -na\n", channel1))
    {
        reportError("netstat", _ssh);
        _ssh->close(channel1);
        delete _ssh;
        return EXIT_FAILURE;
    }

    // Wait for bash prompt, or die in 5 seconds
    if (!_ssh->waitFor(channel1, " $", 5))
    {
        reportError("Wait for netstat", _ssh);
        _ssh->close(channel1);
        delete _ssh;
        return EXIT_FAILURE;
    }

    // Fetch recieved data.
    result = _ssh->read(channel1);

    if (!result)
    {
        reportError("Data received", _ssh);
    }
    else
    {
        std::cout << "Received data:" << std::endl << result << std::endl;
    }
    // Terminate connection by sending "exit" command.
    _ssh->send("exit\n", channel1);

    // Destroy the instance.
    delete _ssh;
    return EXIT_SUCCESS;
}

