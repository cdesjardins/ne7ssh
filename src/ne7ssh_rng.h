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

#ifndef NE7SSH_RNG_H
#define NE7SSH_RNG_H

#include <memory>
#include <botan/auto_rng.h>

class ne7ssh_rng : public Botan::RandomNumberGenerator
{
public:
    ne7ssh_rng()
        : _rng(new Botan::AutoSeeded_RNG())
    {
    }

    ~ne7ssh_rng()
    {
    }

    void randomize(Botan::byte output[], size_t length)
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        _rng->randomize(output, length);
    }

    void clear() throw()
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        _rng->clear();
    }

    std::string name() const
    {
        return _rng->name();
    }

    void reseed(size_t bits_to_collect)
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        _rng->reseed(bits_to_collect);
    }

    void add_entropy_source(Botan::EntropySource* source)
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        _rng->add_entropy_source(source);
    }

    void add_entropy(const Botan::byte in[], size_t length)
    {
        std::unique_lock<std::recursive_mutex> lock(_mutex);
        _rng->add_entropy(in, length);
    }

private:
    std::recursive_mutex _mutex;
    std::unique_ptr<Botan::RandomNumberGenerator> _rng;
};


#endif
