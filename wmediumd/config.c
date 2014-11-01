/*
 *	wmediumd, wireless medium simulator for mac80211_hwsim kernel module
 *	Copyright (c) 2011 cozybit Inc.
 *
 *	Author: Javier Lopez    <jlopex@cozybit.com>
 *		Javier Cardona  <javier@cozybit.com>
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

#include <libconfig.h>
#include <string.h>
#include <stdlib.h>

#include "probability.h"
#include "wmediumd.h"

extern int size;

/*
 *	Funtion to replace all ocurrences of a "old" string for a "new" string
 *	inside a "str" string
 */

char *str_replace(const char *str, const char *old, const char *new)
{
	char *ret, *r;
	const char *p, *q;
	size_t len_str = strlen(str);
	size_t len_old = strlen(old);
	size_t len_new = strlen(new);
	size_t count;

	for(count = 0, p = str; (p = strstr(p, old)); p += len_old)
		count++;

	ret = malloc(count * (len_new - len_old) + len_str + 1);
	if(!ret)
		return NULL;

	for(r = ret, p = str; (q = strstr(p, old)); p = q + len_old) {
		count = q - p;
		memcpy(r, p, count);
		r += count;
		strcpy(r, new);
		r += len_new;
	}
	strcpy(r, p);
	return ret;
}

/*
 *	Writes a char* buffer to a destination file
 */

int write_buffer_to_file(char *file, char *buffer)
{
	FILE *p = NULL;

	p = fopen(file, "w");
	if (p== NULL) {
		return 1;
	}

	fwrite(buffer, strlen(buffer), 1, p);
	fclose(p);

	return 0;
}

/*
 *	Writes a sample configuration with matrix filled with a value to a file
 */

/*
 *	Loads a config file into memory
 */

int load_config(const char *file)
{

	config_t cfg, *cf;
	const config_setting_t *ids;
	int count_ids, i;
	int count_value;

	/*initialize the config file*/
	cf = &cfg;
	config_init(cf);

	/*read the file*/
	if (!config_read_file(cf, file)) {
		printf("Error loading file %s at line:%d, reason: %s\n",
		file,
		config_error_line(cf),
		config_error_text(cf));
		config_destroy(cf);
		exit(EXIT_FAILURE);
    	}

	/*let's parse the values*/
	config_lookup_int(cf, "ifaces.count", &count_value);
	ids = config_lookup(cf, "ifaces.ids");
	count_ids = config_setting_length(ids);

	/*cross check*/
	if (count_value != count_ids) {
		printf("Error on ifaces.count");
		exit(EXIT_FAILURE);
	}

	size = count_ids;
	printf("#_if = %d\n",count_ids);
	/*Initialize the probability*/
	init_probability(count_ids);

	/*Fill the mac_addr*/
	for (i = 0; i < count_ids; i++) {
		u8 addr[ETH_ALEN];
		const char *str =  config_setting_get_string_elem(ids, i);
		string_to_mac_address(str,addr);
		put_mac_address(addr,i);
	}
	/*Print the mac_addr array*/
	print_mac_address_array();

	config_destroy(cf);
	return (EXIT_SUCCESS);
}
