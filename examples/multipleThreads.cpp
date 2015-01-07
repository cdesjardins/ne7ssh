/* An example of ne7ssh library usage. Please change the values in connectWithPassword
   function before compiling.

   This will work with openssh server if default shell of authenticating user is bash.
   When using a different shell or custom prompt replace " $" string in waitFor()
   method with a string corresponding with your shell prompt.

   If you are testing this with later openssh versions, make sure to add this
   option to your server's configuration file to enable password authentication:

   PasswordAuthentication yes
*/
#include <string.h>
#include <ne7ssh.h>
#include <iostream>
#include <thread>
#include <string>

void* thread_proc(int third);

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
    std::cout << argv[0] << " " << ne7ssh::getVersion() << std::endl;

    ne7ssh::create();

    // Set SSH connection options.
    ne7ssh::setOptions("aes128-cbc", "hmac-md5");


    std::thread t1 = std::thread(&thread_proc, 0);
    std::thread t2 = std::thread(&thread_proc, 1);
    std::thread t3 = std::thread(&thread_proc, 2);
    std::thread t4 = std::thread(&thread_proc, 3);

    t1.join();
    t2.join();
    t3.join();
    t4.join();

    ne7ssh::destroy();
    return EXIT_SUCCESS;
}

void* thread_proc(int third)
{
    int channel1, i;
    const char* result;

    for (i = 0; i < 50; i++)
    {
        // Initiate a connection.
        channel1 = ne7ssh::connectWithPassword("remoteHost", 22, "remoteUsr", "password", true, 30);
        if (channel1 < 0)
        {
            reportError("Thread1. Connection", ne7ssh::errors());
            continue;
        }

        // Wait for bash prompt, or die in 5 seconds.
        if (!ne7ssh::waitFor(channel1, " $", 5))
        {
            reportError("Waiting for remote", ne7ssh::errors());
            ne7ssh::close(channel1);
            continue;
        }

        // Send "ls" command.
        if (!ne7ssh::send("ls -al\n", channel1))
        {
            reportError("Send command", ne7ssh::errors());
            ne7ssh::close(channel1);
            continue;
        }

        // Wait for bash prompt, or die in 5 seconds
        if (!ne7ssh::waitFor(channel1, " $", 5))
        {
            reportError("Waiting for remote site", ne7ssh::errors());
            ne7ssh::close(channel1);
            continue;
        }

        // Fetch recieved data.
        result = ne7ssh::read(channel1);
        std::cout << "Data Thread " << third << " " << result << std::endl;

        // Close the connection.
        ne7ssh::send("exit\n", channel1);
    }
    return NULL;
}

