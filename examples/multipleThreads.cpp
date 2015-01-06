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
    ne7ssh* ssh;
    int     thrid;
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
    ne7ssh* _ssh = new ne7ssh();

    // Set SSH connection options.
    _ssh->setOptions("aes128-cbc", "hmac-md5");

    ssh_thrarg_t args[4];
    args[0].ssh = _ssh;
    args[1].ssh = _ssh;
    args[2].ssh = _ssh;
    args[3].ssh = _ssh;

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
    delete _ssh;
    return EXIT_SUCCESS;
}

void* thread_proc(void* initData)
{
    int channel1, i;
    const char* result;
    ne7ssh* _ssh = ((ssh_thrarg_t*) initData)->ssh;
    int thrid = ((ssh_thrarg_t*) initData)->thrid;

    for (i = 0; i < 50; i++)
    {
        // Initiate a connection.
        channel1 = _ssh->connectWithPassword("remoteHost", 22, "remoteUsr", "password", true, 30);
        if (channel1 < 0)
        {
            reportError("Thread1. Connection", _ssh->errors());
            continue;
        }

        // Wait for bash prompt, or die in 5 seconds.
        if (!_ssh->waitFor(channel1, " $", 5))
        {
            reportError("Waiting for remote", _ssh->errors());
            _ssh->close(channel1);
            continue;
        }

        // Send "ls" command.
        if (!_ssh->send("ls -al\n", channel1))
        {
            reportError("Send command", _ssh->errors());
            _ssh->close(channel1);
            continue;
        }

        // Wait for bash prompt, or die in 5 seconds
        if (!_ssh->waitFor(channel1, " $", 5))
        {
            reportError("Waiting for remote site", _ssh->errors());
            _ssh->close(channel1);
            continue;
        }

        // Fetch recieved data.
        result = _ssh->read(channel1);
        printf("Data Thread %i: %s\n\n", thrid, result);

        // Close the connection.
        _ssh->send("exit\n", channel1);
    }
    return NULL;
}

