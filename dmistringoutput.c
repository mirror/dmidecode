/*
 * Generic output functions
 * This file is part of the dmidecode project.
 *
 *   Copyright (C) 2020 Jean Delvare <jdelvare@suse.de>
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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dmistringoutput.h"

const size_t output_size = 50000 * sizeof(char);
char* output;

void spr_init()
{
	output = malloc(output_size);
}
void spr_free()
{
	free(output);
}

void spr_comment(const char *format, ...)
{
	va_list args;

	sprintf(output + strlen(output), "# ");
	va_start(args, format);
	vsprintf(output + strlen(output), format, args);
	va_end(args);
	sprintf(output + strlen(output), "\n");
}

void spr_info(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vsprintf(output + strlen(output), format, args);
	va_end(args);
	sprintf(output + strlen(output), "\n");
}

void spr_handle(const struct dmi_header *h)
{
	sprintf(output + strlen(output), "Handle 0x%04X, DMI type %d, %d bytes\n",
	       h->handle, h->type, h->length);		   
}

void spr_handle_name(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vsprintf(output + strlen(output), format, args);
	va_end(args);
	sprintf(output + strlen(output), "\n");
}

void spr_attr(const char *name, const char *format, ...)
{
	va_list args;

	sprintf(output + strlen(output), "\t%s: ", name);

	va_start(args, format);
	vsprintf(output + strlen(output), format, args);
	va_end(args);
	sprintf(output + strlen(output), "\n");
}

void spr_subattr(const char *name, const char *format, ...)
{
	va_list args;

	sprintf(output + strlen(output), "\t\t%s: ", name);

	va_start(args, format);
	vsprintf(output + strlen(output), format, args);
	va_end(args);
	sprintf(output + strlen(output), "\n");
}

void spr_list_start(const char *name, const char *format, ...)
{
	va_list args;

	sprintf(output + strlen(output), "\t%s:", name);

	/* format is optional, skip value if not provided */
	if (format)
	{
		sprintf(output + strlen(output), " ");
		va_start(args, format);
		vsprintf(output + strlen(output), format, args);
		va_end(args);
	}
	sprintf(output + strlen(output), "\n");
}

void spr_list_item(const char *format, ...)
{
	va_list args;

	sprintf(output + strlen(output), "\t\t");

	va_start(args, format);
	vsprintf(output + strlen(output), format, args);
	va_end(args);
	sprintf(output + strlen(output), "\n");
}

void spr_list_end(void)
{
	/* a no-op for text output */
}

void spr_sep(void)
{
	sprintf(output + strlen(output), "\n");
}

void spr_struct_err(const char *format, ...)
{
	va_list args;

	sprintf(output + strlen(output), "\t");

	va_start(args, format);
	vsprintf(output + strlen(output), format, args);
	va_end(args);
	sprintf(output + strlen(output), "\n");
}

char* get_output()
{
	return output;
}
