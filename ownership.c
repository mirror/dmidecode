/*
 * Compaq Ownership Tag
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
 *   None, this is guess work.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "types.h"
#include "util.h"

#define WORD(x) (*(const u16 *)(x))
#define DWORD(x) (*(const u32 *)(x))

static void ownership(int fd, u32 base, const char *pname, const char *devmem)
{
	u8 *buf;
	int i;
	
	if((buf=malloc(0x51))==NULL)
	{
		perror(pname);
		return;
	}
	
	/* read the ownership tag */
	if(lseek(fd, (off_t)base, SEEK_SET)==-1)
	{
		perror(devmem);
		return;
	}
	if(myread(fd, buf, 0x50, devmem)==-1)
	{
		free(buf);
		exit(1);
	}
	
	/* chop the trailing garbage */
	i=0x4f;
	while(i>=0 && (buf[i]==0x20 || buf[i]==0x00))
		i--;
	buf[i+1]='\0';
	
	/* filter and print */
	if(i>=0)
	{
		for(; i>=0; i--)
		{
			if(buf[i]<32 || (buf[i]>=127 && buf[i]<160))
				buf[i]='?';
		}
		printf("%s\n", (char *)buf);
	}

	free(buf);
}

static u32 decode(const u8 *p)
{
	int i;

	/* integrity checking (lack of checksum) */
	for(i=0; i<p[4]; i++)
	{
		if(p[5+i*10]!='$' || !(p[6+i*10]>='A' && p[6+i*10]<='Z')
			|| !(p[7+i*10]>='A' && p[7+i*10]<='Z')
			|| !(p[8+i*10]>='A' && p[8+i*10]<='Z'))
		{
			printf("\t Abnormal Entry! Please report. [%02x %02x %02x %02x]\n",
				p[5+i*10], p[6+i*10], p[7+i*10], p[8+i*10]);
			return 0;
		}
	}
	
	/* search for the right entry */
	for(i=0; i<p[4]; i++)
		if(memcmp(p+5+i*10, "$ERB", 4)==0)
			return DWORD(p+9+i*10);
	
	return 0;
}

int main(__attribute__ ((unused)) int argc, const char *argv[])
{
	u8 buf[16];
	int fd;
	off_t fp=0xE0000;
	const char *devmem="/dev/mem";
	int ok=0;
	
	if(sizeof(u8)!=1 || sizeof(u16)!=2 || sizeof(u32)!=4)
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

	while(!ok && fp<0xFFFFF)
	{
		if(myread(fd, buf, 16, devmem)==-1)
			exit(1);
		
		if(memcmp((char *)buf, "32OS", 4)==0)
		{
			off_t len=buf[4]*10+5;
			u8 *p;

			if(fp+len-1<=0xFFFFF)
			{
				u32 base;
				
				if((p=malloc(len))==NULL)
				{
					perror("malloc");
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
				}
				if((base=decode(p)))
				{
					ok=1;
					ownership(fd, base, argv[0], devmem);
				}
				else
					lseek(fd, fp+16, SEEK_SET);
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
	
	return 0;
}
