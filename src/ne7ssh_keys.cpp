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

#include "ne7ssh_keys.h"
#include "ne7ssh.h"
#include "ne7ssh_crypt.h"
#include <botan/base64.h>
#include <botan/look_pk.h>
#include <cstdio>
#include <fstream>
#include <ctype.h>
#include <sys/stat.h>

using namespace std;
using namespace Botan;

const std::string ne7ssh_keys::s_headerDSA = "-----BEGIN DSA PRIVATE KEY-----\n";
const std::string ne7ssh_keys::s_footerDSA = "-----END DSA PRIVATE KEY-----\n";
const std::string ne7ssh_keys::s_headerRSA = "-----BEGIN RSA PRIVATE KEY-----\n";
const std::string ne7ssh_keys::s_footerRSA = "-----END RSA PRIVATE KEY-----\n";

ne7ssh_keys::ne7ssh_keys()
    : keyAlgo(0)
{
}

ne7ssh_keys::~ne7ssh_keys()
{
}

bool ne7ssh_keys::generateRSAKeys(const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, uint16 keySize)
{
    std::unique_ptr<RSA_PrivateKey> rsaPrivKey;
    BigInt e, n, d, p, q;
    BigInt dmp1, dmq1, iqmp;
    ne7ssh_string pubKeyBlob;
    ofstream privKeyFile;
    ofstream pubKeyFile;
    std::string privKeyEncoded;
    DER_Encoder encoder;

    if (keySize > MAX_KEYSIZE)
    {
        ne7ssh::errors()->push(-1, "Specified key size: '%i' is larger than allowed maximum.", keySize);
        return false;
    }

    if (keySize < 1024)
    {
        ne7ssh::errors()->push(-1, "Key Size: '%i' is too small. Use at least 1024 key size for RSA keys.", keySize);
        return false;
    }

    rsaPrivKey.reset(new RSA_PrivateKey(*ne7ssh_crypt::s_rng, keySize));

    e = rsaPrivKey->get_e();
    n = rsaPrivKey->get_n();

    d = rsaPrivKey->get_d();
    p = rsaPrivKey->get_p();
    q = rsaPrivKey->get_q();

    dmp1 = d % (p - 1);
    dmq1 = d % (q - 1);
    iqmp = inverse_mod(q, p);

    pubKeyBlob.addString("ssh-rsa");
    pubKeyBlob.addBigInt(e);
    pubKeyBlob.addBigInt(n);

    std::unique_ptr<Base64_Encoder> b64encoder(new Base64_Encoder);
    Pipe base64it(b64encoder.get());
    base64it.process_msg(pubKeyBlob.value());

    SecureVector<Botan::byte> pubKeyBase64 = base64it.read_all();

    pubKeyFile.open(pubKeyFileName);

    if (pubKeyFile.is_open() == false)
    {
        ne7ssh::errors()->push(-1, "Cannot open file where public key is stored. Filename: %s", pubKeyFileName);
        return false;
    }
    pubKeyFile.exceptions(std::ofstream::failbit | std::ofstream::badbit);
    try
    {
        pubKeyFile.write("ssh-rsa ", 8);
        pubKeyFile.write((char*)pubKeyBase64.begin(), (size_t)pubKeyBase64.size());
        pubKeyFile.write(" ", 1);
        pubKeyFile.write(fqdn, strlen(fqdn));
        pubKeyFile.write("\n", 1);
    }
    catch (const std::ofstream::failure &)
    {
        ne7ssh::errors()->push(-1, "I/O error while writting to file: %s.", pubKeyFileName);
        return false;
    }

    privKeyEncoded = PEM_Code::encode(
        DER_Encoder().start_cons(SEQUENCE)
        .encode((size_t)0U)
        .encode(n)
        .encode(e)
        .encode(d)
        .encode(p)
        .encode(q)
        .encode(dmp1)
        .encode(dmq1)
        .encode(iqmp)
        .end_cons()
        .get_contents(), "RSA PRIVATE KEY");

    privKeyFile.open(privKeyFileName);
    if (privKeyFile.is_open() == false)
    {
        ne7ssh::errors()->push(-1, "Cannot open file where the private key is stored. Filename: %s.", privKeyFileName);
        return false;
    }
    privKeyFile.write(privKeyEncoded.c_str(), privKeyEncoded.length());
    if (privKeyFile.fail() == true)
    {
        ne7ssh::errors()->push(-1, "IO error while writting to file: %s.", privKeyFileName);
        return false;
    }
    return true;
}

bool ne7ssh_keys::generateDSAKeys(const char* fqdn, const char* privKeyFileName, const char* pubKeyFileName, uint16 keySize)
{
    DER_Encoder encoder;
    BigInt p, q, g, y, x;
    ne7ssh_string pubKeyBlob;
    ofstream privKeyFile;
    ofstream pubKeyFile;
    std::string privKeyEncoded;

    if (keySize != 1024)
    {
        ne7ssh::errors()->push(-1, "DSA keys must be 1024 bits.");
        return false;
    }

    DL_Group dsaGroup(*ne7ssh_crypt::s_rng, Botan::DL_Group::DSA_Kosherizer, keySize);
    DSA_PrivateKey privDsaKey(*ne7ssh_crypt::s_rng, dsaGroup);
    DSA_PublicKey pubDsaKey = privDsaKey;

    p = dsaGroup.get_p();
    q = dsaGroup.get_q();
    g = dsaGroup.get_g();
    y = pubDsaKey.get_y();
    x = privDsaKey.get_x();

    pubKeyBlob.addString("ssh-dss");
    pubKeyBlob.addBigInt(p);
    pubKeyBlob.addBigInt(q);
    pubKeyBlob.addBigInt(g);
    pubKeyBlob.addBigInt(y);

    std::unique_ptr<Base64_Encoder> b64encoder(new Base64_Encoder);
    Pipe base64it(b64encoder.get());
    base64it.process_msg(pubKeyBlob.value());

    SecureVector<Botan::byte> pubKeyBase64 = base64it.read_all();

    pubKeyFile.open(pubKeyFileName);

    if (pubKeyFile.is_open() == false)
    {
        ne7ssh::errors()->push(-1, "Cannot open file where public key is stored. Filename: %s", pubKeyFileName);
        return false;
    }
    pubKeyFile.exceptions(std::ofstream::failbit | std::ofstream::badbit);
    try
    {
        pubKeyFile.write("ssh-dss ", 8);
        pubKeyFile.write((char*)pubKeyBase64.begin(), pubKeyBase64.size());
        pubKeyFile.write(" ", 1);
        pubKeyFile.write(fqdn, strlen(fqdn));
        pubKeyFile.write("\n", 1);
    }
    catch (const std::ofstream::failure &)
    {
        ne7ssh::errors()->push(-1, "I/O error while writting to file: %s.", pubKeyFileName);
        return false;
    }

    encoder.start_cons(SEQUENCE)
    .encode((size_t)0U)
    .encode(p)
    .encode(q)
    .encode(g)
    .encode(y)
    .encode(x)
    .end_cons();
    privKeyEncoded = PEM_Code::encode(encoder.get_contents(), "DSA PRIVATE KEY");

    privKeyFile.open(privKeyFileName);

    if (privKeyFile.is_open() == false)
    {
        ne7ssh::errors()->push(-1, "Cannot open file where private key is stored. Filename: %s", privKeyFileName);
        return false;
    }

    privKeyFile.write(privKeyEncoded.c_str(), privKeyEncoded.length());
    if (privKeyFile.fail() == true)
    {
        ne7ssh::errors()->push(-1, "I/O error while writting to file: %s.", privKeyFileName);
        return false;
    }

    return true;
}

SecureVector<Botan::byte>& ne7ssh_keys::generateSignature(Botan::SecureVector<Botan::byte>& sessionID, Botan::SecureVector<Botan::byte>& signingData)
{
    this->_signature.clear();
    switch (this->keyAlgo)
    {
        case DSA:
            this->_signature = generateDSASignature(sessionID, signingData);
            return (_signature);

        case RSA:
            this->_signature = generateRSASignature(sessionID, signingData);
            return (_signature);

        default:
            this->_signature.clear();
            return (_signature);
    }
}

SecureVector<Botan::byte> ne7ssh_keys::generateDSASignature(Botan::SecureVector<Botan::byte>& sessionID, Botan::SecureVector<Botan::byte>& signingData)
{
    SecureVector<Botan::byte> sigRaw;
    ne7ssh_string sigData, sig;

    sigData.addVectorField(sessionID);
    sigData.addVector(signingData);
    if (!_dsaPrivateKey)
    {
        ne7ssh::errors()->push(-1, "Private DSA key not initialized.");
        return sig.value();
    }

    std::unique_ptr<PK_Signer> DSASigner(new PK_Signer(*_dsaPrivateKey, "EMSA1(SHA-1)"));
    sigRaw = DSASigner->sign_message(sigData.value(), *ne7ssh_crypt::s_rng);
    if (!sigRaw.size())
    {
        ne7ssh::errors()->push(-1, "Failure to generate DSA signature.");
        return sig.value();
    }

    if (sigRaw.size() != 40)
    {
        ne7ssh::errors()->push(-1, "DSS signature block <> 320 bits. Make sure you are using 1024 bit keys for authentication!");
        sig.clear();
        return sig.value();
    }

    sig.addString("ssh-dss");
    sig.addVectorField(sigRaw);
    return (sig.value());
}

SecureVector<Botan::byte> ne7ssh_keys::generateRSASignature(Botan::SecureVector<Botan::byte>& sessionID, Botan::SecureVector<Botan::byte>& signingData)
{
    SecureVector<Botan::byte> sigRaw;
    ne7ssh_string sigData, sig;

    sigData.addVectorField(sessionID);
    sigData.addVector(signingData);
    if (!_rsaPrivateKey)
    {
        ne7ssh::errors()->push(-1, "Private RSA key not initialized.");
        return sig.value();
    }

    std::unique_ptr<PK_Signer> RSASigner(new PK_Signer(*_rsaPrivateKey, "EMSA3(SHA-1)"));
    sigRaw = RSASigner->sign_message(sigData.value(), *ne7ssh_crypt::s_rng);
    if (!sigRaw.size())
    {
        ne7ssh::errors()->push(-1, "Failure while generating RSA signature.");
        return sig.value();
    }

    sig.addString("ssh-rsa");
    sig.addVectorField(sigRaw);
    return (sig.value());
}

bool ne7ssh_keys::getKeyPairFromFile(const char* privKeyFileName)
{
    ne7ssh_string privKeyStr;
    std::string buffer;
#ifndef WIN32
    struct stat privKeyStatus;

    if (lstat(privKeyFileName, &privKeyStatus) < 0)
    {
        ne7ssh::errors()->push(-1, "Cannot read file status: '%s'.", privKeyFileName);
        return false;
    }

    if ((privKeyStatus.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) != 0)
    {
        ne7ssh::errors()->push(-1, "Private key file permissions are read/write by others: '%s'.", privKeyFileName);
        return false;
    }
#endif
    if (!privKeyStr.addFile(privKeyFileName))
    {
        ne7ssh::errors()->push(-1, "Cannot read PEM file: '%s'.", privKeyFileName);
        return false;
    }

    buffer.assign((const char*)privKeyStr.value().begin(), privKeyStr.length());
    // Find all CR-LF, and remove the CR
    buffer.erase(std::remove(buffer.begin(), buffer.end(), '\r'), buffer.end());

    if ((buffer.find(s_headerRSA) == 0) && (buffer.find(s_footerRSA) == (buffer.length() - s_footerRSA.length())))
    {
        this->keyAlgo = ne7ssh_keys::RSA;
    }
    else if ((buffer.find(s_headerDSA) == 0) && (buffer.find(s_footerDSA) == (buffer.length() - s_footerDSA.length())))
    {
        this->keyAlgo = ne7ssh_keys::DSA;
    }
    else
    {
        ne7ssh::errors()->push(-1, "Encountered unknown PEM file format. Perhaps not an SSH private key file: '%s'.", privKeyFileName);
        return false;
    }

    SecureVector<Botan::byte> keyVector((Botan::byte*)buffer.c_str(), buffer.length());
    switch (this->keyAlgo)
    {
        case DSA:
            if (!getDSAKeys((char*)keyVector.begin(), keyVector.size()))
            {
                return false;
            }
            break;

        case RSA:
            if (!getRSAKeys((char*)keyVector.begin(), keyVector.size()))
            {
                return false;
            }
            break;
    }

    return true;
}

bool ne7ssh_keys::getDSAKeys(char* buffer, uint32 size)
{
//  DataSource_Memory privKeyPEMSrc (privKeyPEMStr);
    SecureVector<Botan::byte> keyDataRaw;
    BigInt p, q, g, y, x;
    char* start;
    size_t version;

    start = buffer + s_headerDSA.length();
    Pipe base64dec(new Base64_Decoder);
    base64dec.process_msg((Botan::byte*)start, size - s_footerDSA.length() - s_headerDSA.length());
    keyDataRaw = base64dec.read_all();

    BER_Decoder decoder(keyDataRaw);

    BER_Decoder sequence = decoder.start_cons(SEQUENCE);
    sequence.decode(version);

    if (version)
    {
        ne7ssh::errors()->push(-1, "Encountered unknown DSA key version.");
        return false;
    }

    sequence.decode(p);
    sequence.decode(q);
    sequence.decode(g);
    sequence.decode(y);
    sequence.decode(x);

    sequence.discard_remaining();
    sequence.verify_end();

    if (p.is_zero() || q.is_zero() || g.is_zero() || y.is_zero() || x.is_zero())
    {
        ne7ssh::errors()->push(-1, "Could not decode the supplied DSA key.");
        return false;
    }

    DL_Group dsaGroup(p, q, g);

    _dsaPrivateKey.reset(new DSA_PrivateKey(*ne7ssh_crypt::s_rng, dsaGroup, x));
    _publicKeyBlob.clear();
    _publicKeyBlob.addString("ssh-dss");
    _publicKeyBlob.addBigInt(p);
    _publicKeyBlob.addBigInt(q);
    _publicKeyBlob.addBigInt(g);
    _publicKeyBlob.addBigInt(y);

    return true;
}

bool ne7ssh_keys::getRSAKeys(char* buffer, uint32 size)
{
    SecureVector<Botan::byte> keyDataRaw;
    BigInt p, q, e, d, n;
    char* start;
    size_t version;

    start = buffer + s_headerRSA.length();
    Pipe base64dec(new Base64_Decoder);
    base64dec.process_msg((Botan::byte*)start, size - s_footerRSA.length() - s_headerRSA.length());
    keyDataRaw = base64dec.read_all();

    BER_Decoder decoder(keyDataRaw);

    BER_Decoder sequence = decoder.start_cons(SEQUENCE);
    sequence.decode(version);

    if (version)
    {
        ne7ssh::errors()->push(-1, "Encountered unknown RSA key version.");
        return false;
    }

    sequence.decode(n);
    sequence.decode(e);
    sequence.decode(d);
    sequence.decode(p);
    sequence.decode(q);

    sequence.discard_remaining();
    sequence.verify_end();

    if (n.is_zero() || e.is_zero() || d.is_zero() || p.is_zero() || q.is_zero())
    {
        ne7ssh::errors()->push(-1, "Could not decode the supplied RSA key.");
        return false;
    }

    _rsaPrivateKey.reset(new RSA_PrivateKey(*ne7ssh_crypt::s_rng, p, q, e, d, n));
    _publicKeyBlob.clear();
    _publicKeyBlob.addString("ssh-rsa");
    _publicKeyBlob.addBigInt(e);
    _publicKeyBlob.addBigInt(n);

    return true;
}

SecureVector<Botan::byte>& ne7ssh_keys::getPublicKeyBlob()
{
    return _publicKeyBlob.value();
}

