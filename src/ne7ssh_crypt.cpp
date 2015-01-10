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

#if !defined WIN32 && !defined(__MINGW32__)
#   include <arpa/inet.h>
#endif

#include "ne7ssh_crypt.h"
#include "ne7ssh_session.h"
#include "ne7ssh_impl.h"
#include "ne7ssh.h"

#include <botan/cbc.h>
#include <botan/look_pk.h>

using namespace Botan;

ne7ssh_crypt::ne7ssh_crypt(std::shared_ptr<ne7ssh_session> session)
    : _session(session),
    _kexMethod(DH_GROUP1_SHA1),
    _hostkeyMethod(SSH_RSA),
    _c2sCryptoMethod(AES128_CBC),
    _s2cCryptoMethod(AES128_CBC),
    _c2sMacMethod(HMAC_MD5),
    _s2cMacMethod(HMAC_MD5),
    _c2sCmprsMethod(NONE),
    _s2cCmprsMethod(NONE),
    _inited(false),
    _encryptBlock(0),
    _decryptBlock(0)
{
}

ne7ssh_crypt::~ne7ssh_crypt()
{
}

bool ne7ssh_crypt::agree(Botan::SecureVector<Botan::byte> &result, const char* local, Botan::SecureVector<Botan::byte> &remote)
{
    ne7ssh_string localAlgos(local, 0);
    ne7ssh_string remoteAlgos(remote, 0);
    char* localAlgo, * remoteAlgo;
    bool match;
    size_t len = 0;

    localAlgos.split(',');
    localAlgos.resetParts();
    remoteAlgos.split(',');
    remoteAlgos.resetParts();

    match = false;
    do
    {
        localAlgo = localAlgos.nextPart();
        if (localAlgo != NULL)
        {
            len = strlen(localAlgo);
            do
            {
                remoteAlgo = remoteAlgos.nextPart();
                if (remoteAlgo != NULL)
                {
                    if (!memcmp(localAlgo, remoteAlgo, len))
                    {
                        match = true;
                        break;
                    }
                }
            } while (remoteAlgo != NULL);
            if (match)
            {
                break;
            }
            remoteAlgos.resetParts();
        }
    } while (localAlgo != NULL);
    if (match)
    {
        result = Botan::SecureVector<Botan::byte>((Botan::byte*)localAlgo, (uint32_t) len);
        return true;
    }
    else
    {
        result.clear();
        return false;
    }
}

bool ne7ssh_crypt::negotiatedKex(Botan::SecureVector<Botan::byte> &kexAlgo)
{
    if (!memcmp(kexAlgo.begin(), "diffie-hellman-group1-sha1", kexAlgo.size()))
    {
        _kexMethod = DH_GROUP1_SHA1;
        return true;
    }
    else if (!memcmp(kexAlgo.begin(), "diffie-hellman-group14-sha1", kexAlgo.size()))
    {
        _kexMethod = DH_GROUP14_SHA1;
        return true;
    }

    ne7ssh::errors()->push(_session->getSshChannel(), "KEX algorithm: '%B' not defined.", &kexAlgo);
    return false;
}

bool ne7ssh_crypt::negotiatedHostkey(Botan::SecureVector<Botan::byte> &hostkeyAlgo)
{
    if (!memcmp(hostkeyAlgo.begin(), "ssh-dss", hostkeyAlgo.size()))
    {
        _hostkeyMethod = SSH_DSS;
        return true;
    }
    else if (!memcmp(hostkeyAlgo.begin(), "ssh-rsa", hostkeyAlgo.size()))
    {
        _hostkeyMethod = SSH_RSA;
        return true;
    }

    ne7ssh::errors()->push(_session->getSshChannel(), "Hostkey algorithm: '%B' not defined.", &hostkeyAlgo);
    return false;
}

bool ne7ssh_crypt::negotiatedCryptoC2s(Botan::SecureVector<Botan::byte> &cryptoAlgo)
{
    if (!memcmp(cryptoAlgo.begin(), "3des-cbc", cryptoAlgo.size()))
    {
        _c2sCryptoMethod = TDES_CBC;
        return true;
    }
    else if (!memcmp(cryptoAlgo.begin(), "aes128-cbc", cryptoAlgo.size()))
    {
        _c2sCryptoMethod = AES128_CBC;
        return true;
    }
    else if (!memcmp(cryptoAlgo.begin(), "aes192-cbc", cryptoAlgo.size()))
    {
        _c2sCryptoMethod = AES192_CBC;
        return true;
    }
    else if (!memcmp(cryptoAlgo.begin(), "aes256-cbc", cryptoAlgo.size()))
    {
        _c2sCryptoMethod = AES256_CBC;
        return true;
    }
    else if (!memcmp(cryptoAlgo.begin(), "blowfish-cbc", cryptoAlgo.size()))
    {
        _c2sCryptoMethod = BLOWFISH_CBC;
        return true;
    }
    else if (!memcmp(cryptoAlgo.begin(), "cast128-cbc", cryptoAlgo.size()))
    {
        _c2sCryptoMethod = CAST128_CBC;
        return true;
    }
    else if (!memcmp(cryptoAlgo.begin(), "twofish-cbc", cryptoAlgo.size()) || !memcmp(cryptoAlgo.begin(), "twofish256-cbc", cryptoAlgo.size()))
    {
        _c2sCryptoMethod = TWOFISH_CBC;
        return true;
    }

    ne7ssh::errors()->push(_session->getSshChannel(), "Cryptographic algorithm: '%B' not defined.", &cryptoAlgo);
    return false;
}

bool ne7ssh_crypt::negotiatedCryptoS2c(Botan::SecureVector<Botan::byte> &cryptoAlgo)
{
    if (!memcmp(cryptoAlgo.begin(), "3des-cbc", cryptoAlgo.size()))
    {
        _s2cCryptoMethod = TDES_CBC;
        return true;
    }
    else if (!memcmp(cryptoAlgo.begin(), "aes128-cbc", cryptoAlgo.size()))
    {
        _s2cCryptoMethod = AES128_CBC;
        return true;
    }
    else if (!memcmp(cryptoAlgo.begin(), "aes192-cbc", cryptoAlgo.size()))
    {
        _s2cCryptoMethod = AES192_CBC;
        return true;
    }
    else if (!memcmp(cryptoAlgo.begin(), "aes256-cbc", cryptoAlgo.size()))
    {
        _s2cCryptoMethod = AES256_CBC;
        return true;
    }
    else if (!memcmp(cryptoAlgo.begin(), "blowfish-cbc", cryptoAlgo.size()))
    {
        _s2cCryptoMethod = BLOWFISH_CBC;
        return true;
    }
    else if (!memcmp(cryptoAlgo.begin(), "cast128-cbc", cryptoAlgo.size()))
    {
        _s2cCryptoMethod = CAST128_CBC;
        return true;
    }
    else if (!memcmp(cryptoAlgo.begin(), "twofish-cbc", cryptoAlgo.size()) || !memcmp(cryptoAlgo.begin(), "twofish256-cbc", cryptoAlgo.size()))
    {
        _s2cCryptoMethod = TWOFISH_CBC;
        return true;
    }

    ne7ssh::errors()->push(_session->getSshChannel(), "Cryptographic method: '%B' not defined.", &cryptoAlgo);
    return false;
}

bool ne7ssh_crypt::negotiatedMacC2s(Botan::SecureVector<Botan::byte> &macAlgo)
{
    if (!memcmp(macAlgo.begin(), "hmac-sha1", macAlgo.size()))
    {
        _c2sMacMethod = HMAC_SHA1;
        return true;
    }
    else if (!memcmp(macAlgo.begin(), "hmac-md5", macAlgo.size()))
    {
        _c2sMacMethod = HMAC_MD5;
        return true;
    }
    else if (!memcmp(macAlgo.begin(), "none", macAlgo.size()))
    {
        _c2sMacMethod = HMAC_NONE;
        return true;
    }

    ne7ssh::errors()->push(_session->getSshChannel(), "HMAC algorithm: '%B' not defined.", &macAlgo);
    return false;
}

bool ne7ssh_crypt::negotiatedMacS2c(Botan::SecureVector<Botan::byte> &macAlgo)
{
    if (!memcmp(macAlgo.begin(), "hmac-sha1", macAlgo.size()))
    {
        _s2cMacMethod = HMAC_SHA1;
        return true;
    }
    else if (!memcmp(macAlgo.begin(), "hmac-md5", macAlgo.size()))
    {
        _s2cMacMethod = HMAC_MD5;
        return true;
    }
    else if (!memcmp(macAlgo.begin(), "none", macAlgo.size()))
    {
        _s2cMacMethod = HMAC_NONE;
        return true;
    }

    ne7ssh::errors()->push(_session->getSshChannel(), "HMAC algorithm: '%B' not defined.", &macAlgo);
    return false;
}

bool ne7ssh_crypt::negotiatedCmprsC2s(Botan::SecureVector<Botan::byte> &cmprsAlgo)
{
    if (!memcmp(cmprsAlgo.begin(), "none", cmprsAlgo.size()))
    {
        _c2sCmprsMethod = NONE;
        return true;
    }
    else if (!memcmp(cmprsAlgo.begin(), "zlib", cmprsAlgo.size()))
    {
        _c2sCmprsMethod = ZLIB;
        return true;
    }

    ne7ssh::errors()->push(_session->getSshChannel(), "Compression algorithm: '%B' not defined.", &cmprsAlgo);
    return false;
}

bool ne7ssh_crypt::negotiatedCmprsS2c(Botan::SecureVector<Botan::byte> &cmprsAlgo)
{
    if (!memcmp(cmprsAlgo.begin(), "none", cmprsAlgo.size()))
    {
        _s2cCmprsMethod = NONE;
        return true;
    }
    else if (!memcmp(cmprsAlgo.begin(), "zlib", cmprsAlgo.size()))
    {
        _s2cCmprsMethod = ZLIB;
        return true;
    }

    ne7ssh::errors()->push(_session->getSshChannel(), "Compression algorithm: '%B' not defined.", &cmprsAlgo);
    return false;
}

bool ne7ssh_crypt::getKexPublic(Botan::BigInt &publicKey)
{
    switch (_kexMethod)
    {
        case DH_GROUP1_SHA1:
            return getDHGroup1Sha1Public(publicKey);

        case DH_GROUP14_SHA1:
            return getDHGroup14Sha1Public(publicKey);

        default:
            ne7ssh::errors()->push(_session->getSshChannel(), "Undefined DH Group: '%s'.", _kexMethod);
            return false;
    }
}

bool ne7ssh_crypt::computeH(Botan::SecureVector<Botan::byte> &result, Botan::SecureVector<Botan::byte> &val)
{
    HashFunction* hashIt;

    switch (_kexMethod)
    {
        case DH_GROUP1_SHA1:
        case DH_GROUP14_SHA1:
            hashIt = global_state().algorithm_factory().make_hash_function("SHA-1");
            break;

        default:
            ne7ssh::errors()->push(_session->getSshChannel(), "Undefined DH Group: '%s' while computing H.", _kexMethod);
            return false;
    }

    if (!hashIt)
    {
        return false;
    }
    _H = hashIt->process(val);
    result = _H;
    delete (hashIt);
    return true;
}

bool ne7ssh_crypt::verifySig(Botan::SecureVector<Botan::byte> &hostKey, Botan::SecureVector<Botan::byte> &sig)
{
    std::shared_ptr<DSA_PublicKey> dsaKey;
    std::shared_ptr<RSA_PublicKey> rsaKey;
    std::unique_ptr<PK_Verifier> verifier;
    ne7ssh_string signature(sig, 0);
    SecureVector<Botan::byte> sigType, sigData;
    bool result = false;

    if (_H.empty())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "H was not initialzed.");
        return false;
    }

    if (!signature.getString(sigType))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Signature without type.");
        return false;
    }
    if (!signature.getString(sigData))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Signature without data.");
        return false;
    }

    switch (_hostkeyMethod)
    {
        case SSH_DSS:
            dsaKey = getDSAKey(hostKey);
            if (!dsaKey)
            {
                ne7ssh::errors()->push(_session->getSshChannel(), "DSA key not generated.");
                return false;
            }
            break;

        case SSH_RSA:
            rsaKey = getRSAKey(hostKey);
            if (!rsaKey)
            {
                ne7ssh::errors()->push(_session->getSshChannel(), "RSA key not generated.");
                return false;
            }
            break;

        default:
            ne7ssh::errors()->push(_session->getSshChannel(), "Hostkey algorithm: %i not supported.", _hostkeyMethod);
            return false;
    }

    switch (_kexMethod)
    {
        case DH_GROUP1_SHA1:
        case DH_GROUP14_SHA1:
            if (dsaKey)
            {
                verifier.reset(new PK_Verifier(*dsaKey, "EMSA1(SHA-1)"));
            }
            else if (rsaKey)
            {
                verifier.reset(new PK_Verifier(*rsaKey, "EMSA3(SHA-1)"));
            }
            break;

        default:
            break;
    }
    if (verifier == NULL)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Key Exchange algorithm: %i not supported.", _kexMethod);
    }
    else
    {
        result = verifier->verify_message(_H, sigData);
        verifier.reset();
    }
    dsaKey.reset();
    rsaKey.reset();

    if (result == false)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Failure to verify host signature.");
        return false;
    }
    else
    {
        return true;
    }
}

std::shared_ptr<DSA_PublicKey> ne7ssh_crypt::getDSAKey(Botan::SecureVector<Botan::byte> &hostKey)
{
    ne7ssh_string hKey;
    SecureVector<Botan::byte> field;
    BigInt p, q, g, y;
    std::shared_ptr<DSA_PublicKey> pubKey;

    hKey.addVector(hostKey);

    if (!hKey.getString(field))
    {
        return 0;
    }
    if (!negotiatedHostkey(field))
    {
        return 0;
    }

    if (!hKey.getBigInt(p))
    {
        return 0;
    }
    if (!hKey.getBigInt(q))
    {
        return 0;
    }
    if (!hKey.getBigInt(g))
    {
        return 0;
    }
    if (!hKey.getBigInt(y))
    {
        return 0;
    }

    DL_Group keyDL(p, q, g);
    pubKey.reset(new DSA_PublicKey(keyDL, y));
    return pubKey;
}

std::shared_ptr<RSA_PublicKey> ne7ssh_crypt::getRSAKey(Botan::SecureVector<Botan::byte> &hostKey)
{
    ne7ssh_string hKey;
    SecureVector<Botan::byte> field;
    BigInt e, n;
    std::shared_ptr<RSA_PublicKey> pubKey;

    hKey.addVector(hostKey);

    if (!hKey.getString(field))
    {
        return 0;
    }
    if (!negotiatedHostkey(field))
    {
        return 0;
    }

    if (!hKey.getBigInt(e))
    {
        return 0;
    }
    if (!hKey.getBigInt(n))
    {
        return 0;
    }
    pubKey.reset(new RSA_PublicKey(n, e));
    return pubKey;
}

bool ne7ssh_crypt::makeKexSecret(Botan::SecureVector<Botan::byte> &result, Botan::BigInt &f)
{
    DH_KA_Operation dhop(*_privKexKey);
    std::unique_ptr<byte> buf(new byte[f.bytes()]);
    Botan::BigInt::encode(buf.get(), f);
    SymmetricKey negotiated = dhop.agree(buf.get(), f.bytes());

    if (!negotiated.length())
    {
        return false;
    }

    BigInt Kint(negotiated.begin(), negotiated.length());
    ne7ssh_string::bn2vector(result, Kint);
    _K = result;
    _privKexKey.reset();
    return true;
}

bool ne7ssh_crypt::getDHGroup1Sha1Public(Botan::BigInt &publicKey)
{
    _privKexKey.reset(new DH_PrivateKey(*ne7ssh_impl::s_rng, DL_Group("modp/ietf/1024")));
    DH_PublicKey pubKexKey = *_privKexKey;

    publicKey = pubKexKey.get_y();
    if (publicKey.is_zero())
    {
        return false;
    }
    else
    {
        return true;
    }
}

bool ne7ssh_crypt::getDHGroup14Sha1Public(Botan::BigInt &publicKey)
{
    _privKexKey.reset(new DH_PrivateKey(*ne7ssh_impl::s_rng, DL_Group("modp/ietf/2048")));
    DH_PublicKey pubKexKey = *_privKexKey;

    publicKey = pubKexKey.get_y();
    if (publicKey.is_zero())
    {
        return false;
    }
    else
    {
        return true;
    }
}

const char* ne7ssh_crypt::getHashAlgo()
{
    switch (_kexMethod)
    {
        case DH_GROUP1_SHA1:
        case DH_GROUP14_SHA1:
            return "SHA-1";

        default:
            ne7ssh::errors()->push(_session->getSshChannel(), "DH Group: %i was not defined.", _kexMethod);
            return 0;
    }
}

const char* ne7ssh_crypt::getCryptAlgo(uint32 crypto)
{
    switch (crypto)
    {
        case TDES_CBC:
            return "TripleDES";

        case AES128_CBC:
            return "AES-128";

        case AES192_CBC:
            return "AES-192";

        case AES256_CBC:
            return "AES-256";

        case BLOWFISH_CBC:
            return "Blowfish";

        case CAST128_CBC:
            return "CAST-128";

        case TWOFISH_CBC:
            return "Twofish";

        default:
            ne7ssh::errors()->push(_session->getSshChannel(), "Cryptographic algorithm: %i was not defined.", crypto);
            return 0;
    }
}

const char* ne7ssh_crypt::getHmacAlgo(uint32 method)
{
    switch (method)
    {
        case HMAC_SHA1:
            return "SHA-1";

        case HMAC_MD5:
            return "MD5";

        case HMAC_NONE:
            return 0;

        default:
            ne7ssh::errors()->push(_session->getSshChannel(), "HMAC algorithm: %i was not defined.", method);
            return 0;
    }
}

uint32 ne7ssh_crypt::getMacKeyLen(uint32 method)
{
    switch (method)
    {
        case HMAC_SHA1:
            return 20;

        case HMAC_MD5:
            return 16;

        case HMAC_NONE:
            return 0;

        default:
            ne7ssh::errors()->push(_session->getSshChannel(), "HMAC algorithm: %i was not defined.", method);
            return 0;
    }
}

uint32 ne7ssh_crypt::getMacDigestLen(uint32 method)
{
    switch (method)
    {
        case HMAC_SHA1:
            return 20;

        case HMAC_MD5:
            return 16;

        case HMAC_NONE:
            return 0;

        default:
            return 0;
    }
}

size_t ne7ssh_crypt::max_keylength_of(const std::string& name)
{
    Algorithm_Factory& af = global_state().algorithm_factory();

    if (const BlockCipher* bc = af.prototype_block_cipher(name))
    {
        return bc->key_spec().maximum_keylength();
    }

    if (const StreamCipher* sc = af.prototype_stream_cipher(name))
    {
        return sc->key_spec().maximum_keylength();
    }

    if (const MessageAuthenticationCode* mac = af.prototype_mac(name))
    {
        return mac->key_spec().maximum_keylength();
    }

    return 0;
}

bool ne7ssh_crypt::makeNewKeys()
{
    const char* algo;
    uint32 key_len, iv_len, macLen;
    SecureVector<Botan::byte> key;
    const Botan::BlockCipher* cipher;
    const Botan::HashFunction* hash_algo;

    algo = getCryptAlgo(_c2sCryptoMethod);
    key_len = max_keylength_of(algo);
    if (key_len == 0)
    {
        return false;
    }
    if (_c2sCryptoMethod == BLOWFISH_CBC)
    {
        key_len = 16;
    }
    else if (_c2sCryptoMethod == TWOFISH_CBC)
    {
        key_len = 32;
    }
    _encryptBlock = iv_len = block_size_of(algo);
    macLen = getMacKeyLen(_c2sMacMethod);
    if (!algo)
    {
        return false;
    }

    if (!compute_key(key, 'A', iv_len))
    {
        return false;
    }
    InitializationVector c2s_iv(key);

    if (!compute_key(key, 'C', key_len))
    {
        return false;
    }
    SymmetricKey c2s_key(key);

    if (!compute_key(key, 'E', macLen))
    {
        return false;
    }
    SymmetricKey c2s_mac(key);

    Algorithm_Factory &af = global_state().algorithm_factory();
    cipher = af.prototype_block_cipher(algo);
    _encrypt.reset(new Pipe(new CBC_Encryption(cipher->clone(), new Null_Padding, c2s_key, c2s_iv)));

    if (macLen)
    {
        hash_algo = af.prototype_hash_function(getHmacAlgo(_c2sMacMethod));
        _hmacOut.reset(new HMAC(hash_algo->clone()));
        _hmacOut->set_key(c2s_mac);
    }
//  if (c2sCmprsMethod == ZLIB) compress = new Pipe (new Zlib_Compression(9));

    algo = getCryptAlgo(_s2cCryptoMethod);
    key_len = max_keylength_of(algo);
    if (key_len == 0)
    {
        return false;
    }
    if (_s2cCryptoMethod == BLOWFISH_CBC)
    {
        key_len = 16;
    }
    else if (_s2cCryptoMethod == TWOFISH_CBC)
    {
        key_len = 32;
    }
    _decryptBlock = iv_len = block_size_of(algo);
    macLen = getMacKeyLen(_c2sMacMethod);
    if (!algo)
    {
        return false;
    }

    if (!compute_key(key, 'B', iv_len))
    {
        return false;
    }
    InitializationVector s2c_iv(key);

    if (!compute_key(key, 'D', key_len))
    {
        return false;
    }
    SymmetricKey s2c_key(key);

    if (!compute_key(key, 'F', macLen))
    {
        return false;
    }
    SymmetricKey s2c_mac(key);

    cipher = af.prototype_block_cipher(algo);
    _decrypt.reset(new Pipe(new CBC_Decryption(cipher->clone(), new Null_Padding, s2c_key, s2c_iv)));

    if (macLen)
    {
        hash_algo = af.prototype_hash_function(getHmacAlgo(_s2cMacMethod));
        _hmacIn.reset(new HMAC(hash_algo->clone()));
        _hmacIn->set_key(s2c_mac);
    }
//  if (s2cCmprsMethod == ZLIB) decompress = new Pipe (new Zlib_Decompression);

    _inited = true;
    return true;
}

bool ne7ssh_crypt::compute_key(Botan::SecureVector<Botan::byte>& key, Botan::byte ID, uint32 nBytes)
{
    SecureVector<Botan::byte> hash, newKey;
    ne7ssh_string hashBytes;
    HashFunction* hashIt;
    const char* algo = getHashAlgo();
    uint32 len;

    if (!algo)
    {
        return false;
    }

    hashIt = global_state().algorithm_factory().make_hash_function(algo);

    if (!hashIt)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Undefined HASH algorithm encountered while computing the key.");
        return false;
    }

    hashBytes.addVectorField(_K);
    hashBytes.addVector(_H);
    hashBytes.addChar(ID);
    hashBytes.addVector(_session->getSessionID());

    hash = hashIt->process(hashBytes.value());
    newKey = hash;
    len = newKey.size();

    while (len < nBytes)
    {
        hashBytes.clear();
        hashBytes.addVectorField(_K);
        hashBytes.addVector(_H);
        hashBytes.addVector(newKey);
        hash = hashIt->process(hashBytes.value());
        newKey += hash;
        len = newKey.size();
    }
    key = Botan::SecureVector<Botan::byte>(newKey.begin(), nBytes);
    delete (hashIt);
    return true;
}

bool ne7ssh_crypt::encryptPacket(Botan::SecureVector<Botan::byte> &crypted, Botan::SecureVector<Botan::byte> &hmac, Botan::SecureVector<Botan::byte> &packet, uint32 seq)
{
    SecureVector<Botan::byte> macStr;
    uint32 nSeq = (uint32)htonl(seq);

    _encrypt->start_msg();
    _encrypt->write(packet.begin(), packet.size());
    _encrypt->end_msg();
//  encrypt->process_msg (packet);
    crypted = _encrypt->read_all(_encrypt->message_count() - 1);

    if (_hmacOut)
    {
        macStr = SecureVector<Botan::byte>((Botan::byte*)&nSeq, 4);
        macStr += packet;
        hmac = _hmacOut->process(macStr);
    }

    return true;
}

bool ne7ssh_crypt::decryptPacket(Botan::SecureVector<Botan::byte> &decrypted, Botan::SecureVector<Botan::byte> &packet, uint32 len)
{
    uint32 pLen = packet.size();

    if (len % _decryptBlock)
    {
        len = len + (len % _decryptBlock);
    }

    if (len > pLen)
    {
        len = pLen;
    }

    _decrypt->process_msg(packet.begin(), len);
    decrypted = _decrypt->read_all(_decrypt->message_count() - 1);
    return true;
}

void ne7ssh_crypt::compressData(Botan::SecureVector<Botan::byte> &buffer)
{
    SecureVector<Botan::byte> tmpVar;
    if (!_compress)
    {
        return;
    }

    tmpVar.swap(buffer);
    _compress->process_msg(tmpVar);
    tmpVar = _compress->read_all(_compress->message_count() - 1);
    buffer = tmpVar;
}

void ne7ssh_crypt::decompressData(Botan::SecureVector<Botan::byte> &buffer)
{
    SecureVector<Botan::byte> tmpVar;
    if (!_decompress)
    {
        return;
    }

    tmpVar.swap(buffer);
    _decompress->process_msg(tmpVar);
    tmpVar = _decompress->read_all(_decompress->message_count() - 1);
    buffer = tmpVar;
}

void ne7ssh_crypt::computeMac(Botan::SecureVector<Botan::byte> &hmac, Botan::SecureVector<Botan::byte> &packet, uint32 seq)
{
    SecureVector<Botan::byte> macStr;
    uint32 nSeq = htonl(seq);

    if (_hmacIn)
    {
        macStr = SecureVector<Botan::byte>((Botan::byte*)&nSeq, 4);
        macStr += packet;
        hmac = _hmacIn->process(macStr);
    }
    else
    {
        hmac.clear();
    }
}

