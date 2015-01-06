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

#include "ne7ssh_kex.h"
#include "ne7ssh.h"
#include <botan/rng.h>

using namespace Botan;

ne7ssh_kex::ne7ssh_kex(std::shared_ptr<ne7ssh_session> session)
    : _session(session)
{
}

ne7ssh_kex::~ne7ssh_kex()
{
}

void ne7ssh_kex::constructLocalKex()
{
    Botan::byte random[16];
    ne7ssh_string myCiphers(ne7ssh::CIPHER_ALGORITHMS, 0);
    ne7ssh_string myMacs(ne7ssh::MAC_ALGORITHMS, 0);
    SecureVector<Botan::byte> tmpCiphers, tmpMacs;
    char* cipher, * hmac;
    size_t len;

    _localKex.clear();
    _localKex.addChar(SSH2_MSG_KEXINIT);

    ne7ssh::s_rng->randomize(random, 16);

    _localKex.addBytes(random, 16);
    _localKex.addString(ne7ssh::KEX_ALGORITHMS);
    _localKex.addString(ne7ssh::HOSTKEY_ALGORITHMS);

    if (ne7ssh::PREFERED_CIPHER.size() > 0)
    {
        myCiphers.split(',');
        myCiphers.resetParts();

        do
        {
            cipher = myCiphers.nextPart();
            if (cipher != NULL)
            {
                len = strlen(cipher);
                if (ne7ssh::PREFERED_CIPHER.compare(cipher) == 0)
                {
                    _ciphers += SecureVector<Botan::byte>((Botan::byte*)cipher, (uint32_t) len);
                }
                else
                {
                    tmpCiphers += SecureVector<Botan::byte>((Botan::byte*)",", 1);
                    tmpCiphers += SecureVector<Botan::byte>((Botan::byte*)cipher, (uint32_t) len);
                }
            }
        } while (cipher != NULL);
    }
    if (_ciphers.size())
    {
        _ciphers += tmpCiphers;
    }
    else
    {
        _ciphers = myCiphers.value();
    }
// _ciphers.append (&null_byte, 1);

    if (ne7ssh::PREFERED_MAC.size() > 0)
    {
        myMacs.split(',');
        myMacs.resetParts();

        do
        {
            hmac = myMacs.nextPart();
            if (hmac != NULL)
            {
                len = strlen(hmac);
                if (ne7ssh::PREFERED_MAC.compare(hmac) == 0)
                {
                    _hmacs += SecureVector<Botan::byte>((Botan::byte*)hmac, (uint32_t) len);
                }
                else
                {
                    tmpMacs += SecureVector<Botan::byte>((Botan::byte*)",", 1);
                    tmpMacs += SecureVector<Botan::byte>((Botan::byte*)hmac, (uint32_t) len);
                }
            }
        } while (hmac != NULL);
    }
    if (_hmacs.size())
    {
        _hmacs += SecureVector<Botan::byte>(tmpMacs);
    }
    else
    {
        _hmacs = myMacs.value();
    }
//  _hmacs.append (&null_byte, 1);

    _localKex.addVectorField(_ciphers);
    _localKex.addVectorField(_ciphers);
    _localKex.addVectorField(_hmacs);
    _localKex.addVectorField(_hmacs);
    _localKex.addString(ne7ssh::COMPRESSION_ALGORITHMS);
    _localKex.addString(ne7ssh::COMPRESSION_ALGORITHMS);
    _localKex.addInt(0);
    _localKex.addInt(0);
    _localKex.addChar('\0');
    _localKex.addInt(0);
}

bool ne7ssh_kex::sendInit()
{
    std::shared_ptr<ne7ssh_transport> transport;

    if (!_session->_transport)
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "No transport. Cannot initialize key exchange.");
        return false;
    }
    transport = _session->_transport;

    constructLocalKex();

    if (!transport->sendPacket(_localKex.value()))
    {
        return false;
    }
    if (!transport->waitForPacket(SSH2_MSG_KEXINIT))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Timeout while waiting for key exchange init reply");
        return false;
    }

    return true;
}

bool ne7ssh_kex::handleInit()
{
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    std::shared_ptr<ne7ssh_crypt> crypto = _session->_crypto;
    SecureVector<Botan::byte> packet;
    uint32 padLen = transport->getPacket(packet);
    ne7ssh_string remoteKex(packet, 17);
    SecureVector<Botan::byte> algos;
    SecureVector<Botan::byte> agreed;

    if (!transport || !crypto)
    {
        return false;
    }
    _remotKex.clear();
    _remotKex.addBytes(packet.begin(), packet.size() - padLen - 1);

    if (!remoteKex.getString(algos))
    {
        return false;
    }
    if (!crypto->agree(agreed, ne7ssh::KEX_ALGORITHMS, algos))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "No compatible key exchange algorithms.");
        return false;
    }
    if (!crypto->negotiatedKex(agreed))
    {
        return false;
    }

    if (!remoteKex.getString(algos))
    {
        return false;
    }
    if (!crypto->agree(agreed, ne7ssh::HOSTKEY_ALGORITHMS, algos))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "No compatible Hostkey algorithms.");
        return false;
    }
    if (!crypto->negotiatedHostkey(agreed))
    {
        return false;
    }

    if (!remoteKex.getString(algos))
    {
        return false;
    }
    if (!crypto->agree(agreed, (char*)_ciphers.begin(), algos))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "No compatible cryptographic algorithms.");
        return false;
    }
    if (!crypto->negotiatedCryptoC2s(agreed))
    {
        return false;
    }

    if (!remoteKex.getString(algos))
    {
        return false;
    }
    if (!crypto->agree(agreed, (char*)_ciphers.begin(), algos))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "No compatible cryptographic algorithms.");
        return false;
    }
    if (!crypto->negotiatedCryptoS2c(agreed))
    {
        return false;
    }

    if (!remoteKex.getString(algos))
    {
        return false;
    }
    if (!crypto->agree(agreed, (char*)_hmacs.begin(), algos))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "No compatible HMAC algorithms.");
        return false;
    }
    if (!crypto->negotiatedMacC2s(agreed))
    {
        return false;
    }

    if (!remoteKex.getString(algos))
    {
        return false;
    }
    if (!crypto->agree(agreed, (char*)_hmacs.begin(), algos))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "No compatible HMAC algorithms.");
        return false;
    }
    if (!crypto->negotiatedMacS2c(agreed))
    {
        return false;
    }

    if (!remoteKex.getString(algos))
    {
        return false;
    }
    if (!crypto->agree(agreed, ne7ssh::COMPRESSION_ALGORITHMS, algos))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "No compatible compression algorithms.");
        return false;
    }
    if (!crypto->negotiatedCmprsC2s(agreed))
    {
        return false;
    }

    if (!remoteKex.getString(algos))
    {
        return false;
    }
    if (!crypto->agree(agreed, ne7ssh::COMPRESSION_ALGORITHMS, algos))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "No compatible compression algorithms.");
        return false;
    }
    if (!crypto->negotiatedCmprsS2c(agreed))
    {
        return false;
    }

    return true;
}

bool ne7ssh_kex::sendKexDHInit()
{
    ne7ssh_string dhInit;
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    std::shared_ptr<ne7ssh_crypt> crypto = _session->_crypto;
    BigInt publicKey;
    SecureVector<Botan::byte> eVector;

    if (!crypto->getKexPublic(publicKey))
    {
        return false;
    }

    dhInit.addChar(SSH2_MSG_KEXDH_INIT);
    dhInit.addBigInt(publicKey);
    ne7ssh_string::bn2vector(eVector, publicKey);
    _e.clear();
    _e.addVector(eVector);

    if (!transport->sendPacket(dhInit.value()))
    {
        return false;
    }

    if (!transport->waitForPacket(SSH2_MSG_KEXDH_REPLY))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Timeout while waiting for key exchange dh reply.");
        return false;
    }
    return true;
}

bool ne7ssh_kex::handleKexDHReply()
{
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    std::shared_ptr<ne7ssh_crypt> crypto = _session->_crypto;
    SecureVector<Botan::byte> packet;
    transport->getPacket(packet);
    if (packet.empty() == true)
    {
        return false;
    }
    ne7ssh_string remoteKexDH(packet, 1);
    SecureVector<Botan::byte> field, fVector, hSig, kVector, hVector;
    BigInt publicKey;

    if (!remoteKexDH.getString(field))
    {
        return false;
    }
    _hostKey.clear();
    _hostKey.addVector(field);

    if (!remoteKexDH.getBigInt(publicKey))
    {
        return false;
    }
    ne7ssh_string::bn2vector(fVector, publicKey);
    _f.clear();
    _f.addVector(fVector);

    if (!remoteKexDH.getString(hSig))
    {
        return false;
    }

    if (!crypto->makeKexSecret(kVector, publicKey))
    {
        return false;
    }
    _k.clear();
    _k.addVector(kVector);

    makeH(hVector);
    if (hVector.empty())
    {
        return false;
    }
    if (!crypto->isInited())
    {
        _session->setSessionID(hVector);
    }

    if (!crypto->verifySig(_hostKey.value(), hSig))
    {
        return false;
    }

    return true;
}

bool ne7ssh_kex::sendKexNewKeys()
{
    std::shared_ptr<ne7ssh_transport> transport = _session->_transport;
    std::shared_ptr<ne7ssh_crypt> crypto = _session->_crypto;
    ne7ssh_string newKeys;

    if (!transport->waitForPacket(SSH2_MSG_NEWKEYS))
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Timeout while waiting for key exchange newkeys reply.");
        return false;
    }

    newKeys.addChar(SSH2_MSG_NEWKEYS);
    if (!transport->sendPacket(newKeys.value()))
    {
        return false;
    }

    if (!crypto->makeNewKeys())
    {
        ne7ssh::errors()->push(_session->getSshChannel(), "Could not make keys.");
        return false;
    }

    return true;
}

void ne7ssh_kex::makeH(Botan::SecureVector<Botan::byte> &hVector)
{
    std::shared_ptr<ne7ssh_crypt> crypto = _session->_crypto;
    ne7ssh_string hashBytes;

    hashBytes.addVectorField(_session->getLocalVersion());
    hashBytes.addVectorField(_session->getRemoteVersion());
    hashBytes.addVectorField(_localKex.value());
    hashBytes.addVectorField(_remotKex.value());
    hashBytes.addVectorField(_hostKey.value());
    hashBytes.addVectorField(_e.value());
    hashBytes.addVectorField(_f.value());
    hashBytes.addVectorField(_k.value());

    crypto->computeH(hVector, hashBytes.value());
}

