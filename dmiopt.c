/*
 * Command line handling of dmidecode
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
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include "config.h"
#include "types.h"
#include "dmiopt.h"

/* Options are global */
struct opt opt;

static u8 *parse_opt_type(u8 *p, const char *arg)
{
	/* Allocate memory on first call only */
	if(p==NULL)
	{
		p=(u8 *)calloc(256, sizeof(u8));
		if(p==NULL)
		{
			perror("calloc");
			return NULL;
		}
	}

	while(*arg!='\0')
	{
		unsigned long val;
		char *next;

		val=strtoul(arg, &next, 0);
		if(next==arg)
		{
			fprintf(stderr, "Invalid type: %s\n", arg);
			goto exit_free;
		}
		if(val>0xff)
		{
			fprintf(stderr, "Invalid type: %lu\n", val);
			goto exit_free;
		}

		p[val]=1;
		arg=next;
		while(*arg==',' || *arg==' ')
			arg++;
	}

	return p;

exit_free:
	free(p);
	return NULL;
}

/* Return -1 on error, 0 on success */
int parse_command_line(int argc, char * const argv[])
{
	int option;
	const char *optstring = "d:ht:uV";
	struct option longopts[]={
		{ "dev-mem", required_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ "type", required_argument, NULL, 't' },
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
			case 't':
				opt.type=parse_opt_type(opt.type, optarg);
				if(opt.type==NULL)
					return -1;
				break;
			case 'u':
				opt.flags|=FLAG_DUMP;
				break;
			case 'V':
				opt.flags|=FLAG_VERSION;
				break;
			case ':':
			case '?':
				return -1;
		}

	return 0;
}

void print_help(void)
{
	static const char *help=
		"Usage: dmidecode [OPTIONS]\n"
		"Options are:\n"
		" -d, --dev-mem FILE     Read memory from device FILE (default: " DEFAULT_MEM_DEV ")\n"
		" -h, --help             Display this help text and exit\n"
		" -t, --type T1[,T2...]  Only display the entries of given type(s)\n"
		" -u, --dump             Do not decode the entries\n"
		" -V, --version          Display the version and exit\n";
	
	printf("%s", help);
}
