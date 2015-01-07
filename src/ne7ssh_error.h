/***************************************************************************
 *   Copyright (C) 2005-2007 by NetSieben Technologies INC		             *
 *   Author: Andrew Useckas                                                *
 *   Email: andrew@netsieben.com                                           *
 *                                                                         *
 *   This program may be distributed under the terms of the Q Public       *
 *   License as defined by Trolltech AS of Norway and appearing in the     *
 *   file LICENSE.QPL included in the packaging of this file.              *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                  *
 ***************************************************************************/

#ifndef NE7SSH_ERROR_H
#define NE7SSH_ERROR_H

#include "ne7ssh_types.h"
#include <mutex>
#include <queue>
#include <map>
#if !defined(WIN32) && !defined(__MINGW32__)
#   include <sys/select.h>
#endif

/**
    @author Andrew Useckas <andrew@netsieben.com>
*/

class Ne7sshError
{
private:

    static std::recursive_mutex _mutex;
    /**
    * Structure for storing error messages.
    */
    std::map<int32, std::queue<std::string> > _errorBuffers;

public:
    /**
     * Ne7sshError constructor.
     */
    SSH_EXPORT Ne7sshError();

    /**
     * Ne7sshError destructor.
     */
    SSH_EXPORT ~Ne7sshError();

    /**
    * Pushes a new error message into the stack.
    * @param channel Specifies the channel to bind the error message to. This is ne7ssh library channel, not the receive or send channels used by the transport layer.
    * @param format Specifies the error message followed by argument in printf format. The following formatting characters are supported: %s,%d,%i,%l,%x. Modifier %u can be used together with decimal to specify an unsigned variable. Returns null if no there are no erros in the Core context.
    * @return True on success, false on failure.
    */
    SSH_EXPORT bool push(int32 channel, const char* format, ...);

    /**
    * Pops an error message from the Core context.
    * @return The last error message in the Core context. The message is removed from the stack.
    */
    SSH_EXPORT const std::string pop();

    /**
    * Pops an error message from the Channel context.
    * @param channel Specifies the channel error message was bound to. This is ne7ssh library channel, not the receive or send channels used by the transport layer.
    * @return The last error message in the Channel context. The message is removed from the stack. Returns null if no there are no erros in the Channel context.
    */
    SSH_EXPORT const std::string pop(int32 channel);

    /**
    * Removes all error messages within Core context from the stack.
    */
    SSH_EXPORT void deleteCoreMsgs();

    /**
    * Removes all error messages within Channel context from the stack.
    * @param channel Specifies the channel error message was bound to. This is ne7ssh library channel, not the receive or send channels used by the transport layer.
    */
    SSH_EXPORT void deleteChannel(int32 channel);
};

#endif
