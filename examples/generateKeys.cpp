/* An example of ne7ssh library usage. This code will generate a DSA key pair
   and store private key in ./privKeyFile and public key in ./pubKeyFile.

   If you are testing this with later openssh versions, make sure to add this
   option to your server's configuration file to enable password authentication:

   PasswordAuthentication yes
*/

#include <ne7ssh.h>
#include <iostream>
#include <sstream>
int main(int argc, char* argv[])
{
    if (argc != 4)
    {
        std::cerr << "Error: Three arguments required: " << argv[0] << " [rsa|dsa] <emailaddr> <keysize>" << std::endl;
        return EXIT_FAILURE;
    }

    ne7ssh* _ssh = new ne7ssh();
    uint16 size;
    std::istringstream (argv[3]) >> size;
    // Generating DSA keys
    if (!_ssh->generateKeyPair(argv[1], argv[2], "./privKeyFile", "./pubKeyFile", size))
    {
        std::string errmsg;
        do
        {
            errmsg = _ssh->errors()->pop();
            if (errmsg.size() > 0)
            {
                std::cerr << "Key gneration failed with last error: " << errmsg << std::endl;
            }
        } while (errmsg.size() > 0);
    }

    delete _ssh;
    return EXIT_SUCCESS;
}

