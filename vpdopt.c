/*
 * Command line handling of vpddecode
 * This file is part of the dmidecode project.
 *
 *   (C) 2005 Jean Delvare <khali@linux-fr.org>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "config.h"
#include "vpdopt.h"


/* Options are global */
struct opt opt;


/*
 * Command line options handling
 */

/* Return -1 on error, 0 on success */
int parse_command_line(int argc, char * const argv[])
{
	int option;
	const char *optstring = "d:huV";
	struct option longopts[]={
		{ "dev-mem", required_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ "dump", no_argument, NULL, 'u' },
		{ "version", no_argument, NULL, 'V' },
		{ 0, 0, 0, 0 }
	};

	while((option=getopt_long(argc, argv, optstring, longopts, NULL))!=-1)
		switch(option)
		{
			case 'd':
				opt.devmem=optarg;
				break;
			case 'h':
				opt.flags|=FLAG_HELP;
				break;
			case 'u':
				opt.flags|=FLAG_DUMP;
				break;
			case 'V':
				opt.flags|=FLAG_VERSION;
				break;
			case '?':
				return -1;
		}

	return 0;
}

void print_help(void)
{
	static const char *help=
		"Usage: vpddecode [OPTIONS]\n"
		"Options are:\n"
		" -d, --dev-mem FILE     Read memory from device FILE (default: " DEFAULT_MEM_DEV ")\n"
		" -h, --help             Display this help text and exit\n"
		" -u, --dump             Do not decode the VPD records\n"
		" -V, --version          Display the version and exit\n";
	
	printf("%s", help);
}
