/*
 * Common "util" functions
 * This file is part of the dmidecode project.
 *
 *   (C) 2002-2003 Jean Delvare <khali@linux-fr>
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

#include <stdio.h>
#include <unistd.h>
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
