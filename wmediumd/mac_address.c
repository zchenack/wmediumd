/*
 *	wmediumd, wireless medium simulator for mac80211_hwsim kernel module
 *	Copyright (c) 2011 cozybit Inc.
 *
 *	Author: Javier Lopez	<jlopex@cozybit.com>
 *		Javier Cardona	<javier@cozybit.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version 2
 *	of the License, or (at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 *	02110-1301, USA.
 */

#include <stdio.h>
#include "mac_address.h"

void string_to_mac_address(const char* str, u8 *addr)
{
    u8 a[ETH_ALEN];
	sscanf(str, "%x:%x:%x:%x:%x:%x", 
	       &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]);

	addr[0] = a[0];
	addr[1] = a[1];
	addr[2] = a[2];
	addr[3] = a[3];
	addr[4] = a[4];
	addr[5] = a[5];
}
