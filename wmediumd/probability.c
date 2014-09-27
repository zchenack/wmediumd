/*
 *	wmediumd, wireless medium simulator for mac80211_hwsim kernel module
 *	Copyright (c) 2011 cozybit Inc.
 *
 *	Author:	Javier Lopez	<jlopex@cozybit.com>
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "probability.h"
#include "ieee80211.h"

static int array_size = 0;

u8 *indexer;

void put_mac_address(u8 *addr, int pos)
{
	int i;
	void *ptr = indexer + ETH_ALEN * pos;
	memcpy(ptr, addr, ETH_ALEN);
}


/*
 * returns the a mac_address ptr for a given index
 */

u8 * get_mac_address(int pos) {

	void * ptr = indexer;
	ptr = ptr + (ETH_ALEN*pos);

	return ((pos >= array_size) ?  NULL : (u8*)ptr);
}

/*
 * 	Returns the position of the address in the array.
 * 	If the mac_address is not found returns -1
 */

int find_pos_by_mac_address(u8 *addr) {

	int i=0;

	void * ptr = indexer;
	while(memcmp(ptr,addr,ETH_ALEN) && i < array_size)
	{
		i++;
		ptr = ptr + ETH_ALEN;
	}

	return ((i >= array_size) ?  -1 :  i);
}

/*
 * 	Prints the values of the Mac Adress Array
 */

void print_mac_address_array() {

	int i=0;
	u8 *ptr = indexer;

	while (i < array_size) {
		printf("A[%d]:%02X:%02X:%02X:%02X:%02X:%02X\n",
		       i, ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
		i++;
		ptr = ptr + ETH_ALEN;
	}
}

/*
 *	Init all the probability data
 *	Returns a pointer to the probability matrix
 */
double * init_probability(int size) {

	array_size = size;
	indexer = malloc(ETH_ALEN*array_size);

	if (indexer==NULL) {
		printf("Problem allocating vector");
		exit(1);
	}
}
