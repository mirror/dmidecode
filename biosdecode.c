/*
 * BIOS Decode
 *
 *   (C) 2000-2002 Alan Cox <alan@redhat.com>
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
 * References:
 *  - DMTF "System Management BIOS Reference Specification"
 *    Version 2.3.3
 *    http://www.dmtf.org/standards/bios.php.
 *	- Intel "Preboot Execution Environment (PXE) Specification"
 *    Version 2.1
 *    http://www.intel.com/labs/manage/wfm/wfmspecs.htm
 *  - ACPI "Advanced Configuration and Power Interface Specification"
 *    Revision 2.0
 *    http://www.acpi.info/spec20.htm
 *  - Phoenix "BIOS32 Service Directory"
 *    Revision 0.4
 *    http://www.phoenix.com/en/support/white+papers-specs/
 *  - Microsoft "Plug and Play BIOS Specification"
 *    Version 1.0A
 *    http://www.microsoft.com/hwdev/tech/PnP/
 *  - Microsoft "PCI IRQ Routing Table Specification"
 *    Version 1.0
 *    http://www.microsoft.com/hwdev/archive/BUSBIOS/pciirq.asp
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include "version.h"
#include "types.h"
#include "util.h"

#ifdef BIGENDIAN
typedef struct {
	u32 h;
	u32 l;
} u64;
#else /* BIGENDIAN */
typedef struct {
	u32 l;
	u32 h;
} u64;
#endif /* BIGENDIAN */

#define WORD(x) (*(const u16 *)(x))
#define DWORD(x) (*(const u32 *)(x))
#define QWORD(x) (*(const u64 *)(x))

struct bios_entry {
	const char *anchor;
	off_t low_address;
	off_t high_address;
	size_t (*length)(const u8 *);
	int (*decode)(const u8*, size_t);
};


/*
 * SMBIOS
 */

static size_t smbios_length(const u8 *p)
{
	return(p[0x05]==0x1E?0x1F:p[0x05]);
}

static int smbios_decode(const u8 *p, size_t len)
{
	if(len<0x1F || !checksum(p, p[0x05])
	 || memcmp("_DMI_", p+0x10, 5)!=0
	 || !checksum(p+0x10, 0x0F))
		return 0;
	
	printf("SMBIOS %u.%u present.\n",
		p[0x06], p[0x07]);
	printf("\tStructure Table Length: %u bytes\n",
		WORD(p+0x16));
	printf("\tStructure Table Address: 0x%08X\n",
		DWORD(p+0x18));
	printf("\tNumber Of Structures: %u\n",
		WORD(p+0x1C));
	printf("\tMaximum Structure Size: %u bytes\n",
		WORD(p+0x08));
	
	return 1;
}

static size_t dmi_length(__attribute__ ((unused)) const u8 *p)
{
	return(0x0F);
}

static int dmi_decode(const u8 *p, size_t len)
{
	if(len<0x0F || !checksum(p, len))
		return 0;
	
	printf("Legacy DMI %u.%u present.\n",
		p[0x0E]>>4, p[0x0E]&0x0F);
	printf("\tStructure Table Length: %u bytes\n",
		WORD(p+0x06));
	printf("\tStructure Table Address: 0x%08X\n",
		DWORD(p+0x08));
	printf("\tNumber Of Structures: %u\n",
		WORD(p+0x0C));
	
	return 1;
}

/*
 * SYSID
 */

static size_t sysid_length(const u8 *p)
{
	return WORD(p+0x08);
}

static int sysid_decode(const u8 *p, size_t len)
{
	if(len<0x11 || !checksum(p, WORD(p+0x08)))
		return 0;
	
	printf("SYSID present.\n");
	printf("\tRevision: %u\n",
		p[0x10]);
	printf("\tStructure Table Address: 0x%08X\n",
		DWORD(p+0x0A));
	printf("\tNumber Of Structures: %u\n",
		WORD(p+0x0E));
	
	return 1;
}

/*
 * PnP
 */

static size_t pnp_length(const u8 *p)
{
	return(p[0x05]);
}

static const char *pnp_event_notification(u8 code)
{
	static const char *notification[]={
		"Not Supported", /* 0x0 */
		"Polling",
		"Asynchronous",
		"Unknown" /* 0x3 */
	};
	
	return notification[code];
}

static int pnp_decode(const u8 *p, size_t len)
{
	if(len<0x21 || !checksum(p, p[0x05]))
		return 0;
	
	printf("PNP BIOS %u.%u present.\n",
		p[0x04]>>4, p[0x04]&0x0F);
	printf("\tEvent Notification: %s\n",
		pnp_event_notification(WORD(p+0x06)&0x03));
	if((WORD(p+0x06)&0x03)==0x01)
		printf("\tEvent Notification Flag Address: 0x%08X\n",
			DWORD(p+0x09));
	printf("\tReal Mode 16-bit Code Address: %04X:%04X\n",
		WORD(p+0x0F), WORD(p+0x0D));
	printf("\tReal Mode 16-bit Data Address: %04X:0000\n",
		WORD(p+0x1B));
	printf("\t16-bit Protected Mode Code Address: 0x%08X\n",
		DWORD(p+0x13)+WORD(p+0x11));
	printf("\t16-bit Protected Mode Data Address: 0x%08X\n",
		DWORD(p+0x1D));
	if(DWORD(p+0x17)!=0)
		printf("\tOEM Device Identifier: %c%c%c%02X%02X\n",
			0x40+((p[0x17]>>2)&0x1F),
			0x40+((p[0x17]&0x03)<<3)+((p[0x18]>>5)&0x07),
			0x40+(p[0x18]&0x1F), p[0x19], p[0x20]);
	
	return 1;
}

/*
 * ACPI
 */

static size_t acpi_length(const u8 *p)
{
	return(p[15]==2?36:20);
}

static const char *acpi_revision(u8 code)
{
	switch(code)
	{
		case 0:
			return " 1.0";
		case 2:
			return " 2.0";
		default:
			return "";
	}
}

static int acpi_decode(const u8 *p, size_t len)
{
	if(len<20 || !checksum(p, 20))
		return 0;
	
	printf("ACPI%s present.\n",
		acpi_revision(p[15]));
	printf("\tOEM Identifier: ");
	fwrite(p+9, 6, 1, stdout); 
	printf("\n");
	printf("\tRSD Table 32-bit Address: 0x%08X\n",
		DWORD(p+16));
	
	if(DWORD(p+20)>len || !checksum(p, DWORD(p+20)))
		return 0;
	
	if(DWORD(p+20)<32) return 1;
	
	printf("\tXSD Table 64-bit Address: 0x%08X%08X\n",
		QWORD(p+24).h, QWORD(p+24).l);
	
	return 1;
}

/*
 * Sony
 */

static size_t sony_length(const u8 *p)
{
	return(p[0x05]);
}

static int sony_decode(const u8 *p, __attribute__ ((unused)) size_t len)
{
	if(!checksum(p, p[0x05]))
		return 0;
	
	printf("Sony system detected.\n");
	
	return 1;
}

/*
 * BIOS32
 */

static size_t bios32_length(const u8 *p)
{
	return p[0x09]<<4;
}

static int bios32_decode(const u8 *p, size_t len)
{
	if(len<0x0A || !checksum(p, p[0x09]<<4))
		return 0;
	
	printf("BIOS32 Service Directory present.\n");
	printf("\tRevision: %u\n",
		p[0x08]);
	printf("\tCalling Interface Address: 0x%08X\n",
		DWORD(p+0x04));
	
	return 1;
}

/*
 * PIR
 */

static void pir_irqs(u16 code)
{
	if(code==0)
		printf(" None");
	else
	{
		u8 i;
		
		for(i=0; i<16; i++)
			if(code&(1<<i))
				printf(" %u", i);
	}
}

static void pir_slot_number(u8 code)
{
	if(code==0)
		printf(" on-board");
	else
		printf(" slot number %u", code);
}

static size_t pir_length(const u8 *p)
{
	return WORD(p+6);
}

static int pir_decode(const u8 *p, size_t len)
{
	int i;
	
	if(len<32 || !checksum(p, WORD(p+6)))
		return 0;
	
	printf("PCI Interrupt Routing %u.%u present.\n",
		p[5], p[4]);
	printf("\tRouter ID: %02x:%02x.%1x\n",
		p[8], p[9]>>3, p[9]&0x07);
	printf("\tExclusive IRQs:");
	pir_irqs(WORD(p+10));
	printf("\n");
	if(DWORD(p+12)!=0)
		printf("\tCompatible Router: %04x:%04x\n",
			WORD(p+12), WORD(p+14));
	if(DWORD(p+16)!=0)
		printf("\tMiniport Data: 0x%08X\n",
			DWORD(p+16));
	
	for(i=1; i<=(WORD(p+6)-32)/16; i++)
	{
		printf("\tSlot Entry %u: ID %02x:%02x,",
			i, p[(i+1)*16], p[(i+1)*16+1]>>3);
		pir_slot_number(p[(i+1)*16+14]);
		printf("\n");
/*		printf("\tSlot Entry %u\n", i);
		printf("\t\tID: %02x:%02x\n",
			p[(i+1)*16], p[(i+1)*16+1]>>3);
		printf("\t\tLink Value for INTA#: %u\n",
			p[(i+1)*16+2]);
		printf("\t\tIRQ Bitmap for INTA#:");
		pir_irqs(WORD(p+(i+1)*16+3));
		printf("\n");
		printf("\t\tLink Value for INTB#: %u\n",
			p[(i+1)*16+5]);
		printf("\t\tIRQ Bitmap for INTB#:");
		pir_irqs(WORD(p+(i+1)*16+6));
		printf("\n");
		printf("\t\tLink Value for INTC#: %u\n",
			p[(i+1)*16+8]);
		printf("\t\tIRQ Bitmap for INTC#:");
		pir_irqs(WORD(p+(i+1)*16+9));
		printf("\n");
		printf("\t\tLink Value for INTD#: %u\n",
			p[(i+1)*16+11]);
		printf("\t\tIRQ Bitmap for INTD#:");
		pir_irqs(WORD(p+(i+1)*16+12));
		printf("\n");
		printf("\t\tSlot Number:");
		pir_slot_number(p[(i+1)*16+14]);
		printf("\n");*/
	}
	
	return 1;
}

/*
 * Main
 */

static struct bios_entry bios_entries[]={
	{ "_SM_", 0xF0000, 0xFFFFF, smbios_length, smbios_decode },
	{ "_DMI_", 0xF0000, 0xFFFFF, dmi_length, dmi_decode },
	{ "_SYSID_", 0xE0000, 0xFFFFF, sysid_length, sysid_decode },
	{ "$PnP", 0xF0000, 0xFFFFF, pnp_length, pnp_decode },
	{ "RSD PTR ", 0xE0000, 0xFFFFF, acpi_length, acpi_decode },
	{ "$SNY", 0xE0000, 0xFFFFF, sony_length, sony_decode },
	{ "_32_", 0xE0000, 0xFFFFF, bios32_length, bios32_decode },
	{ "$PIR", 0xF0000, 0xFFFFF, pir_length, pir_decode },
	{ NULL, 0, 0, NULL, NULL }
};

int main(__attribute__ ((unused)) int argc, const char *argv[])
{
	u8 buf[16];
	int fd;
	off_t fp=0xE0000;
	const char *devmem="/dev/mem";
	
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
	
	printf("# biosdecode %s\n", VERSION);
	while(fp<0xFFFFF)
	{
		int i;
		
		if(myread(fd, buf, 16, devmem)==-1)
			exit(1);
		
		for(i=0; bios_entries[i].anchor!=NULL; i++)
		{
			if(strncmp((char *)buf, bios_entries[i].anchor, strlen(bios_entries[i].anchor))==0
			 && fp>=bios_entries[i].low_address
			 && fp<bios_entries[i].high_address)
			{
				off_t len=bios_entries[i].length(buf);
				u8 *p;
				
				if(fp+len-1<=bios_entries[i].high_address)
				{
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
					if(bios_entries[i].decode(p, len))
						fp+=(((len-1)>>4)<<4);
					lseek(fd, fp+16, SEEK_SET);
					free(p);
				}
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
