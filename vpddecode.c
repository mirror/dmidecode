/*
 * IBM Vital Product Data decoder
 *
 *   (C) 2003-2005 Jean Delvare <khali@linux-fr.org>
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
 *
 *   For the avoidance of doubt the "preferred form" of this code is one which
 *   is in an open unpatent encumbered format. Where cryptographic key signing
 *   forms part of the process of creating an executable the information 
 *   including keys needed to generate an equivalently functional executable
 *   are deemed to be part of the source code.
 *
 * References:
 *  - IBM "Using the BIOS Build ID to identify IBM Thinkpad systems"
 *    Revision 2005-02-16
 *    http://www-307.ibm.com/pc/support/site.wss/MIGR-45120.html
 *
 * Notes:
 *  - Main part of the code is taken directly from biosdecode, with an
 *    additional lookup table for the product name.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "version.h"
#include "config.h"
#include "types.h"
#include "util.h"

/* Options are global */
struct opt
{
	const char* devmem;
	unsigned int flags;
};
static struct opt opt;

#define FLAG_VERSION            (1<<0)
#define FLAG_HELP               (1<<1)

static const char *product_name(const char *id)
{
	/* Please keep IDs in alphabetical order */
	static const char *name[]={
		"AP", "eServer xSeries 336", /* added 2005-02-01,
		                                reported by David Rosala,
		                                confirmed by Scott Denham */
		"GE", "eServer xSeries 345", /* added 2004-06-11,
		                                reported by Doug Brenner */
		"HR", "Thinkpad 560E",
		"HV", "Thinkpad 760C/CD/L/LD",
		"HX", "Thinkpad 760E/ED/X/XD/XL or 765/L/D (9385XGA)",
		"HY", "Thinkpad 760E/EL/ELD (9320SVGA)",
		"HZ", "Thinkpad 760ED/EL (9385SVGA)",
		"I0", "Thinkpad 560",
		"I1", "Thinkpad 380/D/E/ED or 385D/ED",
		"I4", "Thinkpad 535/E",
		"I5", "Thinkpad 365X/XD",
		"I7", "Thinkpad 770",
		"I8", "Thinkpad 560X",
		"I9", "Thinkpad 310/E or 315D/ED (Please report!)",
		"IA", "Thinkpad 535X",
		"IB", "Thinkpad 600",
		"IC", "Thinkpad 380X/XD or 385XD",
		"ID", "Thinkpad 770/E/ED",
		"IE", "Thinkpad 560Z",
		"IF", "Thinkpad 380X/XD or 385XD",
		"IG", "Thinkpad 380Z",
		"IH", "Thinkpad 600E",
		"II", "Thinkpad 770X/XD",
		"IJ", "Thinkpad 390 or i17xx",
		"IK", "Thinkpad i14xx",
		"IL", "Thinkpad 390",
		"IM", "Thinkpad 570",
		"IN", "Thinkpad 600E",
		"IO", "Thinkpad 770X",
		"IQ", "Thinkpad 390E",
		"IR", "Thinkpad 240",
		"IS", "Thinkpad 390X",
		"IT", "Thinkpad 600X",
		"IU", "Thinkpad 570E",
		"IV", "Thinkpad A20p",
		"IW", "Thinkpad A20m",
		"IX", "Thinkpad i1400 or i1500",
		"IY", "Thinkpad T20",
		"IZ", "Thinkpad X20 or X21", /* updated 2003-11-29 (IBM) */
		"JP", "eServer xSeries 205", /* added 2004-04-30,
		                                reported by Bernd Krumboeck */
		"KP", "eServer xSeries 346", /* added 2005-02-01,
		                                reported by David Rosala,
		                                confirmed by Scott Denham */
		"KQ", "Thinkpad i1200 or i1300",
		"KR", "Thinkpad i1400 or i1500",
		"KS", "Thinkpad 240X",
		"KT", "Thinkpad i1400 or i1500",
		"KU", "Thinkpad A21e", /* type 2628 only */
		"KV", "Transnote",
		"KW", "Thinkpad i1200 or i1300",
		"KX", "Thinkpad A21m or A22m", /* added 2003-11-11,
		                                  reported by Klaus Ade Johnstad,
		                                  confirmed by Pamela Huntley */
		"KY", "Thinkpad A21p or A22p", /* fixed 2003-11-29 (IBM) */
		"KZ", "Thinkpad T21", /* fixed 2003-11-29 (IBM) */
		"NV", "PC 300PL", /* added 2004-04-02,
		                     reported by Shawn Starr */
		"OP", "Intellistation Z10", /* added 2005-02-17,
		                               reported by Scott Denham */
		"PD", "PC 300GL", /* added 2004-04-14,
		                     reported by Roger Koot */
		"PI", "Netvista A40/p", /* added 2004-02-23,
		                           updated 2004-03-24,
		                           reported by Zing Zing Shishak */
		"PJ", "PC 300GL", /* added 2004-03-23,
		                     reported by Roger Koot */
		"PL", "Intellistation M-Pro", /* added 2004-04-15,
		                                 reported by Mark Syms */
		"PN", "Intellistation A10", /* added 2005-02-17,
		                               reported by Scott Denham */
		"PT", "Netvista A20", /* added 2003-12-28,
		                         reported by Ramiro Barreiro */
		"RE", "eServer xSeries 445", /* added 2003-12-17,
		                                reported by Josef Moellers */
		"RD", "eServer xSeries 365", /* added 2005-02-01,
		                                reported by David Rosala */
		"T2", "eServer xSeries 335", /* added 2004-06-11,
		                                reported by Doug Brenner */
		"TT", "eServer xSeries 330", /* added 2003-12-03,
		                                reported by Hugues Lepesant */
		"10", "Thinkpad A21e or A22e", /* Celeron models */
		"11", "Thinkpad 240Z",
		"13", "Thinkpad A22m", /* 2628-Sxx models */
		"15", "Thinkpad i1200",
		"16", "Thinkpad T22",
		"17", "Thinkpad i1200",
		"18", "Thinkpad S30",
		"1A", "Thinkpad T23",
		"1B", "Thinkpad A22e", /* Pentium models */
		"1C", "Thinkpad R30",
		"1D", "Thinkpad X22, X23 or X24",
		"1E", "Thinkpad A30/p",
		"1F", "Thinkpad R31",
		"1G", "Thinkpad A31/p",
		"1I", "Thinkpad T30",
		"1K", "Thinkpad X30",
		"1M", "Thinkpad R32",
		"1N", "Thinkpad A31/p",
		"1O", "Thinkpad R40", /* types 2681, 2682 and 2683 */
		"1P", "Thinkpad R40", /* added 2003-11-29 (IBM),
		                         types 2722, 2723 and 2724 */
		"1Q", "Thinkpad X31",
		"1R", "Thinkpad T40, T41, R50, R50p or R51", /* updated 2003-11-29 (IBM),
		                                                updated 2004-11-08,
								reported by Marco Wertejuk */
		"1S", "Thinkpad R40e", /* added 2003-11-29 (IBM) */
		"1T", "Thinkpad G40",
		"1W", "Thinkpad R50e", /* added 2005-02-17 (IBM) */
		"1Y", "Thinkpad T43/p", /* added 2005-02-17 (IBM) */
		"20", "Netvista A22p or M41", /* added 2003-10-09,
		                                 updated 2004-02-23,
		                                 updated 2004-03-24 */
		"24", "Netvista M42", /* added 2004-03-27,
		                         reported by Paul Sturm */
		"2A", "Thinkcentre M50", /* added 2004-03-19,
		                            reported by Rafael Avila de Espindola */
		NULL, "Unknown, please report!"
	};
	
	int i=0;
	
	/*
	 * This lookup algorithm admittedly performs poorly, but
	 * improving it is just not worth it.
	 */
	while(name[i*2]!=NULL && memcmp(id, name[i*2], 2)!=0)
		i++;
	
	return name[i*2+1];
}

static void print_entry(const char *name, const u8 *p, size_t len)
{
	size_t i;
	
	printf("%s: ", name);
	for(i=0; i<len; i++)
	{
		/* ASCII filtering */
		if(p[i]>=32 && p[i]<127)
			printf("%c", p[i]);
		else if(p[i]!=0)
			printf(".");
	}
	printf("\n");
}

static int decode(const u8 *p)
{
	if(p[5]<0x30)
		return 0;
	
	/* XSeries have longer records. */
	if(!(p[5]>=0x46 && checksum(p, 0x46))
	/* Some Netvista seem to work with this. */
	&& !(checksum(p, 0x30))
	/* The Thinkpad/Thinkcentre checksum does *not* include the first
	   13 bytes. */
	&& !(checksum(p+0x0D, 0x30-0x0D)))
	{
		/* A few systems have a bad checksum (xSeries 330, 335 and 345 with
		   early BIOS) but the record is otherwise valid. */
		printf("Bad checksum! Please report.\n");
	}
	
	print_entry("BIOS Build ID", p+0x0D, 9);
	printf("Product Name: %s\n", product_name((const char *)(p+0x0D)));
	print_entry("Box Serial Number", p+0x16, 7);
	print_entry("Motherboard Serial Number", p+0x1D, 11);
	print_entry("Machine Type/Model", p+0x28, 7);
	
	if(p[5]<0x45)
		return 1;
	
	print_entry("BIOS Release Date", p+0x30, 8);
	print_entry("Default Flash Image File Name", p+0x38, 13);
	
	return 1;
}

/* Return -1 on error, 0 on success */
static int parse_command_line(int argc, char * const argv[])
{
	int option;
	const char *optstring = "d:hV";
	struct option longopts[]={
		{ "dev-mem", required_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
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
			case 'V':
				opt.flags|=FLAG_VERSION;
				break;
			case ':':
			case '?':
				return -1;
		}

	return 0;
}

static void print_help(void)
{
	static const char *help=
		"Usage: vpddecode [OPTIONS]\n"
		"Options are:\n"
		" -d, --dev-mem FILE     Read memory from device FILE (default: " DEFAULT_MEM_DEV ")\n"
		" -h, --help             Display this help text and exit\n"
		" -V, --version          Display the version and exit\n";
	
	printf("%s", help);
}

int main(int argc, char * const argv[])
{
	u8 *buf;
	int found=0;
	off_t fp;
	
	if(sizeof(u8)!=1)
	{
		fprintf(stderr, "%s: compiler incompatibility\n", argv[0]);
		exit(255);
	}
	
	/* Set default option values */
	opt.devmem=DEFAULT_MEM_DEV;
	opt.flags=0;

	if(parse_command_line(argc, argv)<0)
		exit(2);

	if(opt.flags & FLAG_HELP)
	{
		print_help();
		return 0;
	}

	if(opt.flags & FLAG_VERSION)
	{
		printf("%s\n", VERSION);
		return 0;
	}

	printf("# vpddecode %s\n", VERSION);

	if((buf=mem_chunk(0xF0000, 0x10000, opt.devmem))==NULL)
		exit(1);

	for(fp=0; fp<=0xFFF0; fp+=16)
	{
		u8 *p=buf+fp;

		if(memcmp((char *)p, "\252\125VPD", 5)==0
		&& fp+p[5]-1<=0xFFFF
		&& decode(p))
			found++;
	}

	free(buf);
	
	if(!found)
		printf("# No VPD structure found, sorry.\n");
	
	return 0;
}
