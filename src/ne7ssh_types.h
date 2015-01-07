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

#ifndef NE7SSH_TYPES_H
#define NE7SSH_TYPES_H

#include <cstdint>

#if defined(WIN32) || defined(__MINGW32)
#   if defined(_WINDLL) || defined(_USRDLL) || defined(_CONSOLE) || defined(_WINDOWS)
#       ifdef NE7SSH_EXPORTS
#        define SSH_EXPORT __declspec(dllexport)
#      else
#       ifndef NE7SSH_STATIC
#        define SSH_EXPORT __declspec(dllimport)
#       else
#        define SSH_EXPORT
#       endif
#      endif
#   else
#       define SSH_EXPORT
#   endif
#else
#  define SSH_EXPORT
#endif

#ifndef int64_defined
#define int64_defined
typedef int64_t int64;
#endif

#ifndef uint64_defined
#define uint64_defined
typedef uint64_t uint64;
#endif

#ifndef int32_defined
#define int32_defined
typedef int32_t int32;
#endif

#ifndef uint32_defined
#define uint32_defined
typedef uint32_t uint32;
#endif

#ifndef int16_defined
#define int16_defined
typedef int16_t int16;
#endif

#ifndef uint16_defined
#define uint16_defined
typedef uint16_t uint16;
#endif

#ifndef int8_defined
#define int8_defined
typedef int8_t int8;
#endif

#ifndef uint8_defined
#define uint8_defined
typedef uint8_t uint8;
#endif

#ifndef Byte_defined
#define Byte_defined
typedef uint8_t Byte;
#endif

#if defined(WIN32) || defined(__MINGW32__)
#  define UNREF_PARAM(x) x
#else
#  define UNREF_PARAM(x)
#endif

#endif

