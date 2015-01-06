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
void* thread_proc(void* initData);

struct ssh_thrarg_t
{
    std::shared_ptr<ne7ssh> ssh;
    int thrid;
};

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

int main(/*int argc, char* argv[]*/)
{
    std::shared_ptr<ne7ssh> ssh = ne7ssh::ne7sshCreate();

    // Set SSH connection options.
    ssh->setOptions("aes128-cbc", "hmac-md5");

    ssh_thrarg_t args[4];
    args[0].ssh = ssh;
    args[1].ssh = ssh;
    args[2].ssh = ssh;
    args[3].ssh = ssh;

    args[0].thrid = 1;
    args[1].thrid = 2;
    args[2].thrid = 3;
    args[3].thrid = 4;

    std::thread t1 = std::thread(&thread_proc, &args[0]);
    std::thread t2 = std::thread(&thread_proc, &args[1]);
    std::thread t3 = std::thread(&thread_proc, &args[2]);
    std::thread t4 = std::thread(&thread_proc, &args[3]);

    t1.join();
    t2.join();
    t3.join();
    t4.join();
    return EXIT_SUCCESS;
}

void* thread_proc(void* initData)
{
    int channel1, i;
    const char* result;
    std::shared_ptr<ne7ssh> ssh = ((ssh_thrarg_t*) initData)->ssh;
    int thrid = ((ssh_thrarg_t*) initData)->thrid;

    for (i = 0; i < 50; i++)
    {
        // Initiate a connection.
        channel1 = ssh->connectWithPassword("remoteHost", 22, "remoteUsr", "password", true, 30);
        if (channel1 < 0)
        {
            reportError("Thread1. Connection", ssh->errors());
            continue;
        }

        // Wait for bash prompt, or die in 5 seconds.
        if (!ssh->waitFor(channel1, " $", 5))
        {
            reportError("Waiting for remote", ssh->errors());
            ssh->close(channel1);
            continue;
        }

        // Send "ls" command.
        if (!ssh->send("ls -al\n", channel1))
        {
            reportError("Send command", ssh->errors());
            ssh->close(channel1);
            continue;
        }

        // Wait for bash prompt, or die in 5 seconds
        if (!ssh->waitFor(channel1, " $", 5))
        {
            reportError("Waiting for remote site", ssh->errors());
            ssh->close(channel1);
            continue;
        }

        // Fetch recieved data.
        result = ssh->read(channel1);
        printf("Data Thread %i: %s\n\n", thrid, result);

        // Close the connection.
        ssh->send("exit\n", channel1);
    }
    return NULL;
}

