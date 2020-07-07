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
#include "dmioutput.h"

const size_t output_size = 4096 * sizeof(char);
const size_t outout_threshold = 4096;
size_t next_realloc_ratio = 1;
char* output;

void pr_init()
{
	output = malloc(output_size);
	output[0] = '\0';
}
void pr_free()
{
	free(output);
}

void output_realloc()
{
	if ( (next_realloc_ratio * output_size) - strlen(output) < outout_threshold)
	{
		next_realloc_ratio++;
		output = realloc(output, next_realloc_ratio * output_size);
	}
}

void pr_comment(const char *format, ...)
{
	output_realloc();
	va_list args;

	sprintf(output + strlen(output), "# ");
	va_start(args, format);
	vsprintf(output + strlen(output), format, args);
	va_end(args);
	sprintf(output + strlen(output), "\n");
}

void pr_info(const char *format, ...)
{
	output_realloc();
	va_list args;

	va_start(args, format);
	vsprintf(output + strlen(output), format, args);
	va_end(args);
	sprintf(output + strlen(output), "\n");
}

void pr_handle(const struct dmi_header *h)
{
	output_realloc();
	sprintf(output + strlen(output), "Handle 0x%04X, DMI type %d, %d bytes\n",
	       h->handle, h->type, h->length);		   
}

void pr_handle_name(const char *format, ...)
{
	output_realloc();
	va_list args;

	va_start(args, format);
	vsprintf(output + strlen(output), format, args);
	va_end(args);
	sprintf(output + strlen(output), "\n");
}

void pr_attr(const char *name, const char *format, ...)
{
	output_realloc();
	va_list args;

	sprintf(output + strlen(output), "\t%s: ", name);

	va_start(args, format);
	vsprintf(output + strlen(output), format, args);
	va_end(args);
	sprintf(output + strlen(output), "\n");
}

void pr_subattr(const char *name, const char *format, ...)
{
	output_realloc();
	va_list args;

	sprintf(output + strlen(output), "\t\t%s: ", name);

	va_start(args, format);
	vsprintf(output + strlen(output), format, args);
	va_end(args);
	sprintf(output + strlen(output), "\n");
}

void pr_list_start(const char *name, const char *format, ...)
{
	output_realloc();
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

void pr_list_item(const char *format, ...)
{
	output_realloc();
	va_list args;

	sprintf(output + strlen(output), "\t\t");

	va_start(args, format);
	vsprintf(output + strlen(output), format, args);
	va_end(args);
	sprintf(output + strlen(output), "\n");
}

void pr_list_end(void)
{
	/* a no-op for text output */
}

void pr_sep(void)
{
	output_realloc();
	sprintf(output + strlen(output), "\n");
}

void pr_struct_err(const char *format, ...)
{
	output_realloc();
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
