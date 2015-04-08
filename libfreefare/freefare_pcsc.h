/*-
 * Copyright (C) 2009, 2010, Romain Tartiere, Romuald Conty.
 * 
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 * 
 * $Id$
 */

#ifndef __FREEFARE_PCSC_H__
#define __FREEFARE_PCSC_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __APPLE__
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif

#include "freefare.h"

#ifdef __cplusplus
    extern "C" {
#endif // __cplusplus


struct pcsc_context {
	SCARDCONTEXT context;
	LPSTR readers;
};

void		 pcsc_init(struct pcsc_context** context);
void		 pcsc_exit(struct pcsc_context* context);
LONG		 pcsc_list_devices(struct pcsc_context* context, LPSTR* string);

MifareTag	*freefare_get_tags_pcsc (struct pcsc_context *context, const char *reader);
MifareTag	 freefare_tag_new_pcsc(struct pcsc_context *context, const char *reader);

#ifdef __cplusplus
    }
#endif // __cplusplus


#endif
