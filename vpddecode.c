/*
 * IBM Vital Product Data decoder
 *
 *   (C) 2003 Jean Delvare <khali@linux-fr.org>
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
 *    Revision "November 17, 2003"
 *    http://www.pc.ibm.com/qtechinfo/MIGR-45120.html
 *
 * Notes:
 *  - Main part of the code is taken directly from biosdecode, with an
 *    additional lookup table for the product name.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "version.h"
#include "types.h"
#include "util.h"

static const char *product_name(const char *id)
{
	static const char *name[]={
		"HR", "Thinkpad 650E",
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
		"RE", "eServer xSeries 445", /* added 2003-12-17,
		                                reported by Josef Moellers */
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
		"1R", "Thinkpad T40, T41, R50 or R50p", /* updated 2003-11-29 (IBM) */
		"1S", "Thinkpad R40e", /* added 2003-11-29 (IBM) */
		"1T", "Thinkpad G40",
		"20", "Netvista 6823", /* added 2003-10-09 */
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
	
	/* XSeries have longer records and a different checksumming method. */
	if(!(p[5]>=0x46 && checksum(p, 0x46))
	/* The checksum does *not* include the first 13 bytes. */
	&& !(checksum(p+0x0D, 0x30-0x0D)))
		/* A few systems have a bad checksum (xSeries 330, 335 and 345 with
		   early BIOS) but the record is otherwise valid. */
		printf("Bad checksum! Please report.\n");
	
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

int main(int argc, const char *argv[])
{
	u8 buf[16];
	int fd, found=0;
	off_t fp=0xF0000;
	const char *devmem="/dev/mem";
	
	if(sizeof(u8)!=1)
	{
		fprintf(stderr,"%s: compiler incompatibility\n", argv[0]);
		exit(255);
	}
	
	if(argc>=2)
		devmem=argv[1];
	if((fd=open(devmem, O_RDONLY))==-1 || lseek(fd, fp, SEEK_SET)==-1)
	{
		perror(devmem);
		exit(1);
	}

	printf("# vpddecode %s\n", VERSION);
	while(fp<0xFFFFF)
	{
		if(myread(fd, buf, 16, devmem)==-1)
			exit(1);
		
		if(memcmp((char *)buf, "\252\125VPD", 5)==0)
		{
			off_t len=buf[5];
			u8 *p;

			if(fp+len-1<=0xFFFFF)
			{
				if((p=malloc(len))==NULL)
				{
					perror(argv[0]);
					exit(1);
				}

				memcpy(p, buf, 16);
				if(len>16)
				{
					/* buffer completion */
					if(myread(fd, p+16, len-16, devmem)==-1)
					{
						free(p);
						exit(1);
					}
					lseek(fd, fp+16, SEEK_SET);
				}

				if(decode(p))
					found++;
				free(p);
			}
		}
		fp+=16;
	}
	
	if(close(fd)==-1)
	{
		perror(devmem);
		exit(1);
	}
	
	if(!found)
		printf("# No VPD structure found, sorry.\n");
	
	return 0;
}
