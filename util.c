/*
 * Common "util" functions
 * This file is part of the dmidecode project.
 *
 *   (C) 2002-2004 Jean Delvare <khali@linux-fr>
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
 */

#include <sys/types.h>
#include <sys/stat.h>

#ifdef USE_MMAP
#include <sys/mman.h>
#ifndef MAP_FAILED
#define MAP_FAILED ((void *) -1)
#endif /* !MAP_FAILED */
#endif /* USE MMAP */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "types.h"
#include "util.h"

int myread(int fd, u8 *buf, size_t count, const char *prefix)
{
	ssize_t r=1;
	size_t r2=0;
	
	while(r2!=count && r!=0)
	{
		r=read(fd, buf+r2, count-r2);
		if(r==-1)
		{
			if(errno!=EINTR)
			{
				close(fd);
				perror(prefix);
				return -1;
			}
		}
		else
			r2+=r;
	}
	
	if(r2!=count)
	{
		close(fd);
		fprintf(stderr, "%s: Unexpected end of file\n", prefix);
		return -1;
	}
	
	return 0;
}

int checksum(const u8 *buf, size_t len)
{
	u8 sum=0;
	size_t a;
	
	for(a=0; a<len; a++)
		sum+=buf[a];
	return (sum==0);
}

/*
 * Copy a physical memory chunk into a memory buffer.
 * This function allocates memory.
 */
void *mem_chunk(off_t base, off_t len, const char *devmem)
{
	void *p;
	int fd;
#ifdef USE_MMAP
	size_t mmoffset;
	void *mmp;
#endif
	
	if((fd=open(devmem, O_RDONLY))==-1)
	{
		perror(devmem);
		return NULL;
	}
	
	if((p=malloc(len))==NULL)
		return NULL;
	
#ifdef USE_MMAP
	mmoffset=base%getpagesize();
	/*
	 * Please note that we don't use mmap() for performance reasons here,
	 * but to workaround problems many people encountered when trying
	 * to read from /dev/mem using regular read() calls.
	 */
	mmp=mmap(0, mmoffset+len, PROT_READ, MAP_SHARED, fd, base-mmoffset);
	if(mmp==MAP_FAILED)
	{
		fprintf(stderr, "%s: ", devmem);
		perror("mmap");
		free(p);
		return NULL;
	}
	
	memcpy(p, (u8 *)mmp+mmoffset, len);
	
	if(munmap(mmp, mmoffset+0x20)==-1)
	{
		fprintf(stderr, "%s: ", devmem);
		perror("munmap");
	}
#else /* USE_MMAP */
	if(lseek(fd, base, SEEK_SET)==-1)
	{
		fprintf(stderr, "%s: ", devmem);
		perror("lseek");
		free(p);
		return NULL;
	}
	
	if(myread(fd, p, len, devmem)==-1)
	{
		free(p);
		return NULL;
	}
#endif /* USE_MMAP */
	
	if(close(fd)==-1)
		perror(devmem);
	
	return p;
}
