/*
 * DMI Decode
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
 * Unless specified otherwise, all references are aimed at the "System
 * Management BIOS Reference Specification, Version 2.3.4" document,
 * available from http://www.dmtf.org/standards/smbios.
 *
 * Note to contributors:
 * Please reference every value you add or modify, especially if the
 * information does not come from the above mentioned specification.
 *
 * Additional references:
 *	- Intel AP-485 revision 23
 *    "Intel Processor Identification and the CPUID Instruction"
 *    http://developer.intel.com/design/xeon/applnots/241618.htm
 *  - DMTF Master MIF version 030621
 *    "DMTF approved standard groups"
 *    http://www.dmtf.org/standards/dmi
 *  - IPMI 1.5 revision 1.1
 *    "Intelligent Platform Management Interface Specification"
 *    http://developer.intel.com/design/servers/ipmi/spec.htm
 */

#include <sys/types.h>
#include <sys/stat.h>
#ifdef USE_MMAP
#include <sys/mman.h>
#endif /* USE MMAP */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include "version.h"
#include "types.h"
#include "util.h"

static const char *out_of_spec = "<OUT OF SPEC>";
static const char *bad_index = "<BAD INDEX>";

/*
 * The specification isn't very clear on endianness problems, so we better
 * have macros for these. It also helps us solve problems on systems that
 * don't support non-aligned memory access. This isn't a big issue IMHO,
 * since SMBIOS/DMI is intended mainly for Intel and compatible systems,
 * which are little-endian and support non-aligned memory access. Anyway,
 * you may use the following defines to control the way it works:
 * - Define BIGENDIAN on big-endian systems.
 * - Define ALIGNMENT_WORKAROUND if your system doesn't support
 *   non-aligned memory access. In this case, we use a slower, but safer,
 *   memory access method.
 * - If it happens that the table is supposed to be always little-endian
 *   ordered regardless of the architecture, define TABLE_LITTLEENDIAN.
 * You most probably will have to define none or the three of them.
 */

#ifndef TABLE_LITTLEENDIAN
#	ifdef BIGENDIAN
	typedef struct {
		u32 h;
		u32 l;
	} u64;
#	else /* BIGENDIAN */
	typedef struct {
		u32 l;
		u32 h;
	} u64;
#	endif /* BIGENDIAN */
#	ifdef ALIGNMENT_WORKAROUND
#		ifdef BIGENDIAN
#		define WORD(x) (u16)((x)[1]+((x)[0]<<8))
#		define DWORD(x) (u32)((x)[3]+((x)[2]<<8)+((x)[1]<<16)+((x)[0]<<24))
#		define QWORD(x) (U64(DWORD(x+4), DWORD(x)))
#		else /* BIGENDIAN */
#		define WORD(x) (u16)((x)[0]+((x)[1]<<8))
#		define DWORD(x) (u32)((x)[0]+((x)[1]<<8)+((x)[2]<<16)+((x)[3]<<24))
#		define QWORD(x) (U64(DWORD(x), DWORD(x+4)))
#		endif /* BIGENDIAN */
#	else /* ALIGNMENT_WORKAROUND */
#	define WORD(x) (u16)(*(u16 *)(x))
#	define DWORD(x) (u32)(*(u32 *)(x))
#	define QWORD(x) (*(u64 *)(x))
#	endif /* ALIGNMENT_WORKAROUND */
#else /* TABLE_LITTLEENDIAN */
typedef struct {
	u32 l;
	u32 h;
} u64;
#define WORD(x) (u16)((x)[0]+((x)[1]<<8))
#define DWORD(x) (u32)((x)[0]+((x)[1]<<8)+((x)[2]<<16)+((x)[3]<<24))
#define QWORD(x) (U64(DWORD(x), DWORD(x+4)))
#endif /* TABLE_LITTLEENDIAN */

#if defined ALIGNMENT_WORKAROUND || defined TABLE_LITTLEENDIAN
static u64 U64(u32 low, u32 high)
{
	u64 self;
	
	self.l=low;
	self.h=high;
	
	return self;
}
#endif

struct dmi_header
{
	u8 type;
	u8 length;
	u16 handle;
};

#if ((defined BIGENDIAN && defined TABLE_LITTLEENDIAN) || defined ALIGNMENT_WORKAROUND)
#define HANDLE(x) WORD((u8 *)&(x->handle))
#else
#define HANDLE(x) x->handle
#endif


/*
 * Type-independant Stuff
 */

static const char *dmi_string(struct dmi_header *dm, u8 s)
{
	char *bp=(char *)dm;
	size_t i;

	if(s==0)
		return "Not Specified";
	
	bp+=dm->length;
	while(s>1 && *bp)
	{
		bp+=strlen(bp);
		bp++;
		s--;
	}
	
	if(!*bp)
		return bad_index;
	
	/* ASCII filtering */
	for(i=0; i<strlen(bp); i++)
		if(bp[i]<32 || bp[i]==127)
			bp[i]='.';
	
	return bp;
}

static const char *dmi_smbios_structure_type(u8 code)
{
	static const char *type[]={
		"BIOS", /* 0 */
		"System",
		"Base Board",
		"Chassis",
		"Processor",
		"Memory Controler",
		"Memory Module",
		"Cache",
		"Port Connector",
		"System Slots",
		"On Board Devices",
		"OEM Strings",
		"System Configuration Options",
		"BIOS Language",
		"Group Associations",
		"System Event Log",
		"Physical Memory Array",
		"Memory Device",
		"32-bit Memory Error",
		"Memory Array Mapped Address",
		"Memory Device Mapped Address",
		"Built-in Pointing Device",
		"Portable Battery",
		"System Reset",
		"Hardware Security",
		"System Power Controls",
		"Voltage Probe",
		"Cooling Device",
		"Temperature Probe",
		"Electrical Current Probe",
		"Out-of-band Remote Access",
		"Boot Integrity Services",
		"System Boot",
		"64-bit Memory Error",
		"Management Device",
		"Management Device Component",
		"Management Device Threshold Data",
		"Memory Channel",
		"IPMI Device",
		"Power Supply" /* 39 */
	};
	
	if(code<=39)
		return(type[code]);
	return out_of_spec;
}

static int dmi_bcd_range(u8 value, u8 low, u8 high)
{
	if(value>0x99 || (value&0x0F)>0x09)
		return 0;
	if(value<low || value>high)
		return 0;
	return 1;
}

static void dmi_dump(struct dmi_header *h, const char *prefix)
{
	int row, i;
	const char *s;
	
	printf("%sHeader and Data:\n", prefix);
	for(row=0; row<((h->length-1)>>4)+1; row++)
	{
		printf("%s\t", prefix);
		for(i=0; i<16 && i<h->length-(row<<4); i++)
			printf("%s%02X", i?" ":"", ((u8 *)h)[(row<<4)+i]);
		printf("\n");
	}

	if(((u8 *)h)[h->length] || ((u8 *)h)[h->length+1])
	{
		printf("%sStrings:\n", prefix);
		i=1;
		while((s=dmi_string(h, i++))!=bad_index)
			printf("%s\t%s\n", prefix, s);
	}
}

/*
 * 3.3.1 BIOS Information (Type 0)
 */

static void dmi_bios_runtime_size(u32 code)
{
	if(code&0x000003FF)
		printf(" %u bytes", code);
	else
		printf(" %u kB", code>>10);
}

static void dmi_bios_characteristics(u64 code, const char *prefix)
{
	/* 3.3.1.1 */
	static const char *characteristics[]={
		"BIOS characteristics not supported", /* 3 */
		"ISA is supported",
		"MCA is supported",
		"EISA is supported",
		"PCI is supported",
		"PC Card (PCMCIA) is supported",
		"PNP is supported",
		"APM is supported",
		"BIOS is upgradeable",
		"BIOS shadowing is allowed",
		"VLB is supported",
		"ESCD support is available",
		"Boot from CD is supported",
		"Selectable boot is supported",
		"BIOS ROM is socketed",
		"Boot from PC Card (PCMCIA) is supported",
		"EDD is supported",
		"Japanese floppy for NEC 9800 1.2 MB is supported (int 13h)",
		"Japanese floppy for Toshiba 1.2 MB is supported (int 13h)",
		"5.25\"/360 KB floppy services are supported (int 13h)",
		"5.25\"/1.2 MB floppy services are supported (int 13h)",
		"3.5\"/720 KB floppy services are supported (int 13h)",
		"3.5\"/2.88 MB floppy services are supported (int 13h)",
		"Print screen service is supported (int 5h)",
		"8042 keyboard services are supported (int 9h)",
		"Serial services are supported (int 14h)",
		"Printer services are supported (int 17h)",
		"CGA/mono video services are supported (int 10h)",
		"NEC PC-98" /* 31 */
	};
	int i;
	
	/*
	 * This isn't very clear what this bit is supposed to mean
	 */
	if(code.l&(1<<3))
	{
		printf("%s%s\n",
			prefix, characteristics[0]);
		return;
	}
	
	for(i=4; i<=31; i++)
		if(code.l&(1<<i))
			printf("%s%s\n",
				prefix, characteristics[i-3]);
}

static void dmi_bios_characteristics_x1(u8 code, const char *prefix)
{
	/* 3.3.1.2.1 */
	static const char *characteristics[]={
		"ACPI is supported", /* 0 */
		"USB legacy is supported",
		"AGP is supported",
		"I2O boot is supported",
		"LS-120 boot is supported",
		"ATAPI Zip drive boot is supported",
		"IEEE 1394 boot is supported",
		"Smart battery is supported" /* 7 */
	};
	int i;
	
	for(i=0; i<=7; i++)
		if(code&(1<<i))
			printf("%s%s\n",
				prefix, characteristics[i]);
}

static void dmi_bios_characteristics_x2(u8 code, const char *prefix)
{
	/* 3.3.1.2.2 */
	static const char *characteristics[]={
		"BIOS boot specification is supported", /* 0 */
		"Function key-initiated network boot is supported" /* 1 */
	};
	int i;
	
	for(i=0; i<=1; i++)
		if(code&(1<<i))
			printf("%s%s\n",
				prefix, characteristics[i]);
}

/*
 * 3.3.2 System Information (Type 1)
 */

static void dmi_system_uuid(u8 *p)
{
	int only0xFF=1, only0x00=1;
	int i;
	
	for(i=0; i<16 && (only0x00 || only0xFF); i++)
	{
		if(p[i]!=0x00) only0x00=0;
		if(p[i]!=0xFF) only0xFF=0;
	}
	
	if(only0xFF)
	{
		printf(" Not Present");
		return;
	}
	if(only0x00)
	{
		printf(" Not Settable");
		return;
	}
	
	printf(" %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
		p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
}

static const char *dmi_system_wake_up_type(u8 code)
{
	/* 3.3.2.1 */
	static const char *type[]={
		"Reserved", /* 0x00 */
		"Other",
		"Unknown",
		"APM Timer",
		"Modem Ring",
		"LAN Remote",
		"Power Switch",
		"PCI PME#",
		"AC Power Restored" /* 0x08 */
	};
	
	if(code<=0x08)
		return type[code];
	return out_of_spec;
}

/*
 * 3.3.3 Base Board Information (Type 2)
 */

static void dmi_base_board_features(u8 code, const char *prefix)
{
	/* 3.3.3.1 */
	static const char *features[]={
		"Board is a hosting board", /* 0 */
		"Board requires at least one daughter board",
		"Board is removable",
		"Board is replaceable",
		"Board is hot swappable" /* 4 */
	};
	
	if((code&0x1F)==0)
		printf(" None\n");
	else
	{
		int i;
		
		printf("\n");
		for(i=0; i<=4; i++)
			if(code&(1<<i))
				printf("%s%s\n",
					prefix, features[i]);
	}
}

static const char *dmi_base_board_type(u8 code)
{
	/* 3.3.3.2 */
	static const char *type[]={
		"Unknown", /* 0x01 */
		"Other",
		"Server Blade",
		"Connectivity Switch",
		"System Management Module",
		"Processor Module",
		"I/O Module",
		"Memory Module",
		"Daughter Board",
		"Motherboard",
		"Processor+Memory Module",
		"Processor+I/O Module",
		"Interconnect Board" /* 0x0D */
	};
	
	if(code>=0x01 && code<=0x0D)
		return type[code-0x01];
	return out_of_spec;
}

static void dmi_base_board_handlers(u8 count, u8 *p, const char *prefix)
{
	int i;
	
	printf("%sContained Object Handlers: %u\n",
		prefix, count);
	for(i=0; i<count; i++)
		printf("%s\t0x%04X\n",
			prefix, WORD(p+sizeof(u16)*i));
}

/*
 * 3.3.4 Chassis Information (Type 3)
 */

static const char *dmi_chassis_type(u8 code)
{
	/* 3.3.4.1 */
	static const char *type[]={
		"Other", /* 0x01 */
		"Unknown",
		"Desktop",
		"Low Profile Desktop",
		"Pizza Box",
		"Mini Tower",
		"Tower",
		"Portable",
		"Laptop",
		"Notebook",
		"Hand Held",
		"Docking Station",
		"All In One",
		"Sub Notebook",
		"Space-saving",
		"Lunch Box",
		"Main Server Chassis", /* master.mif says System */
		"Expansion Chassis",
		"Sub Chassis",
		"Bus Expansion Chassis",
		"Peripheral Chassis",
		"RAID Chassis",
		"Rack Mount Chassis",
		"Sealed-case PC",
		"Multi-system" /* 0x19 */
	};
	
	if(code>=0x01 && code<=0x19)
		return type[code-0x01];
	return out_of_spec;
}

static const char *dmi_chassis_lock(u8 code)
{
	static const char *lock[]={
		"Not Present", /* 0x00 */
		"Present" /* 0x01 */
	};
	
	return lock[code];
}

static const char *dmi_chassis_state(u8 code)
{
	/* 3.3.4.2 */
	static const char *state[]={
		"Other", /* 0x01 */
		"Unknown",
		"Safe", /* master.mif says OK */
		"Warning",
		"Critical",
		"Non-recoverable" /* 0x06 */
	};
	
	if(code>=0x01 && code<=0x06)
		return(state[code-0x01]);
	return out_of_spec;
}

static const char *dmi_chassis_security_status(u8 code)
{
	/* 3.3.4.3 */
	static const char *status[]={
		"Other", /* 0x01 */
		"Unknown",
		"None",
		"External Interface Locked Out",
		"External Interface Enabled" /* 0x05 */
	};
	
	if(code>=0x01 && code<=0x05)
		return(status[code-0x01]);
	return out_of_spec;
}

static void dmi_chassis_height(u8 code)
{
	if(code==0x00)
		printf(" Unspecified");
	else
		printf(" %u U", code);
}

static void dmi_chassis_power_cords(u8 code)
{
	if(code==0x00)
		printf(" Unspecified");
	else
		printf(" %u", code);
}

static void dmi_chassis_elements(u8 count, u8 len, u8 *p, const char *prefix)
{
	int i;
	
	printf("%sContained Elements: %u\n",
		prefix, count);
	for(i=0; i<count; i++)
	{
		if(len>=0x03)
		{
			printf("%s\t%s (",
				prefix, p[i*len]&0x80?
				dmi_smbios_structure_type(p[i*len]&0x7F):
				dmi_base_board_type(p[i*len]&0x7F));
			if(p[1+i*len]==p[2+i*len])
				printf("%u", p[1+i*len]);
			else
				printf("%u-%u", p[1+i*len], p[2+i*len]);
			printf(")\n");
		}
	}
}

/*
 * 3.3.5 Processor Information (Type 4)
 */

static const char *dmi_processor_type(u8 code)
{
	/* 3.3.5.1 */
	static const char *type[]={
		"Other", /* 0x01 */
		"Unknown",
		"Central Processor",
		"Math Processor",
		"DSP Processor",
		"Video Processor" /* 0x06 */
	};
	
	if(code>=0x01 && code<=0x06)
		return type[code-0x01];
	return out_of_spec;
}

static const char *dmi_processor_family(u8 code)
{
	/* 3.3.5.2 */
	static const char *family[256]={
		NULL, /* 0x00 */
		"Other",
		"Unknown",
		"8086",
		"80286",
		"80386",
		"80486",
		"8087",
		"80287",
		"80387",
		"80487",
		"Pentium",
		"Pentium Pro",
		"Pentium II",
		"Pentium MMX",
		"Celeron",
		"Pentium II Xeon",
		"Pentium III",
		"M1",
		"M2",
		NULL, /* 0x14 */
		NULL,
		NULL,
		NULL, /* 0x17 */
		"Duron",
		"K5",
		"K6",
		"K6-2",
		"K6-3",
		"Athlon",
		"AMD2900",
		"K6-2+",
		"Power PC",
		"Power PC 601",
		"Power PC 603",
		"Power PC 603+",
		"Power PC 604",
		"Power PC 620",
		"Power PC x704",
		"Power PC 750",
		NULL, /* 0x28 */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,/* 0x2F */
		"Alpha",
		"Alpha 21064",
		"Alpha 21066",
		"Alpha 21164",
		"Alpha 21164PC",
		"Alpha 21164a",
		"Alpha 21264",
		"Alpha 21364",
		NULL, /* 0x38 */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 0x3F */
		"MIPS",
		"MIPS R4000",
		"MIPS R4200",
		"MIPS R4400",
		"MIPS R4600",
		"MIPS R10000",
		NULL, /* 0x46 */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 0x4F */
		"SPARC",
		"SuperSPARC",
		"MicroSPARC II",
		"MicroSPARC IIep",
		"UltraSPARC",
		"UltraSPARC II",
		"UltraSPARC IIi",
		"UltraSPARC III",
		"UltraSPARC IIIi",
		NULL, /* 0x59 */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 0x5F */
		"68040",
		"68xxx",
		"68000",
		"68010",
		"68020",
		"68030",
		NULL, /* 0x66 */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 0x6F */
		"Hobbit",
		NULL, /* 0x71 */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 0x77 */
		"Crusoe TM5000",
		"Crusoe TM3000",
		NULL, /* 0x7A */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 0x7F */
		"Weitek",
		NULL, /* 0x81 */
		"Itanium",
		"Athlon 64",
		"Opteron",
		NULL, /* 0x85 */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 0x8F */
		"PA-RISC",
		"PA-RISC 8500",
		"PA-RISC 8000",
		"PA-RISC 7300LC",
		"PA-RISC 7200",
		"PA-RISC 7100LC",
		"PA-RISC 7100",
		NULL, /* 0x97 */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 0x9F */
		"V30",
		NULL, /* 0xA1 */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 0xAF */
		"Pentium III Xeon",
		"Pentium III Speedstep",
		"Pentium 4",
		"Xeon",
		"AS400",
		"Xeon MP",
		"Athlon XP",
		"Athlon MP",
		"Itanium 2",
		"Pentium M",
		NULL, /* 0xBA */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 0xC7 */
		"IBM390",
		"G4",
		"G5",
		NULL, /* 0xCB */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 0xF9 */
		"i860",
		"i960",
		NULL, /* 0xFC */
		NULL,
		NULL,
		NULL /* 0xFF */
		/* master.mif has values beyond that, but they can't be used for DMI */
	};
	
	if(family[code]!=NULL)
		return family[code];
	return out_of_spec;
}

static void dmi_processor_id(u8 type, u8 *p, const char *version, const char *prefix)
{
	/* Intel AP-485 revision 23, table 5 */
	static const char *flags[32]={
		"FPU (Floating-point unit on-chip)", /* 0 */
		"VME (Virtual mode extension)",
		"DE (Debugging extension)",
		"PSE (Page size extension)",
		"TSC (Time stamp counter)",
		"MSR (Model specific registers)",
		"PAE (Physical address extension)",
		"MCE (Machine check exception)",
		"CX8 (CMPXCHG8 instruction supported)",
		"APIC (On-chip APIC hardware supported)",
		NULL, /* 10 */
		"SEP (Fast system call)",
		"MTRR (Memory type range registers)",
		"PGE (Page global enable)",
		"MCA (Machine check architecture)",
		"CMOV (Conditional move instruction supported)",
		"PAT (Page attribute table)",
		"PSE-36 (36-bit page size extension)",
		"PSN (Processor serial number present and enabled)",
		"CLFSH (CLFLUSH instruction supported)",
		NULL, /* 20 */
		"DS (Debug store)",
		"ACPI (ACPI supported)",
		"MMX (MMX technology supported)",
		"FXSR (Fast floating-point save and restore)",
		"SSE (Streaming SIMD extensions)",
		"SSE2 (Streaming SIMD extensions 2)",
		"SS (Self-snoop)",
		"HTT (Hyper-threading technology)",
		"TM (Thermal monitor supported)",
		NULL, /* 30 */
		"SBF (Signal break on FERR)" /* 31 */
	};
	/*
	 * Extra flags are now returned in the ECX register when one calls
	 * the CPUID instruction. Their means are explained in table 6, but
	 * DMI doesn't support this yet.
	 */
	u32 eax;
	int cpuid=0;

	/*
	 * This might help learn about new processors supporting the
	 * CPUID instruction or another form of identification.
	 */
	printf("%sID: %02X %02X %02X %02X %02X %02X %02X %02X\n",
		prefix, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);

	if(type==0x05) /* 80386 */
	{
		u16 dx=WORD(p);
		/*
		 * 80386 have a different signature.
		 */
		printf("%sSignature: Type %X, Family %X, Major Stepping %X, Minor Stepping %X\n",
			prefix, dx>>12, (dx>>8)&0xF, (dx>>4)&0xF, dx&0xF);
		return;
	}
	if(type==0x06) /* 80486 */
	{
		u16 dx=WORD(p);
		/*
		 * Not all 80486 CPU support the CPUID instruction, we have to find
		 * wether the one we have here does or not. Note that this trick
		 * works only because we know that 80486 must be little-endian.
		 */
		if((dx&0x0F00)==0x0400 && ((dx&0x00F0)==0x0040 || (dx&0x00F0)>=0x0070))
			cpuid=1;
	}
	else if((type>=0x0B && type<=0x13) /* Intel, Cyrix */
	|| (type>=0x18 && type<=0x1D) || type==0x1F /* AMD */
	|| (type>=0xB0 && type<=0xB3) /* Intel */
	|| (type>=0xB5 && type<=0xB7) /* Intel, AMD */
	|| (type==0xB9) /* Intel */
	|| (type==0x83 || type==0x84)) /* AMD 64-bit */
		cpuid=1;
	else if(type==0x01)
	{
		/*
		 * Some X86-class CPU have family "Other". In this case, we use
		 * the version string to determine if they are known to support the
		 * CPUID instruction.
		 */
		if(strcmp(version, "AMD Athlon(TM) Processor")==0)
			cpuid=1;
		else
			return;
	}
	else /* not X86-class */
		return;
	
	eax=DWORD(p);
	printf("%sSignature: Type %X, Family %X, Model %X, Stepping %X\n",
		prefix, (eax>>12)&0x3, ((eax>>16)&0xFF0)+((eax>>8)&0x00F),
		((eax>>12)&0xF0)+((eax>>4)&0x0F), eax&0xF);
	if(cpuid)
	{
		u32 edx=DWORD(p+4);
		
		printf("%sFlags:", prefix);
		if((edx&0x3FF7FDFF)==0)
			printf(" None\n");
		else
		{
			int i;
			
			printf("\n");
			for(i=0; i<=31; i++)
				if(flags[i]!=NULL && edx&(1<<i))
					printf("%s\t%s\n", prefix, flags[i]);
		}
	}
}

static void dmi_processor_voltage(u8 code)
{
	/* 3.3.5.4 */
	static const char *voltage[]={
		"5.0 V", /* 0 */
		"3.3 V",
		"2.9 V" /* 2 */
	};
	int i;
	
	if(code&0x80)
		printf(" %.1f V", (float)(code&0x7f)/10);
	else
	{
		for(i=0; i<=2; i++)
			if(code&(1<<i))
				printf(" %s", voltage[i]);
		if(code==0x00)
			printf(" Unknown");
	}
}

static void dmi_processor_frequency(u16 code)
{
	if(code)
		printf(" %u MHz", code);
	else
		printf(" Unknown");
}

static const char *dmi_processor_status(u8 code)
{
	static const char *status[]={
		"Unknown", /* 0x00 */
		"Enabled",
		"Disabled By User",
		"Disabled By BIOS",
		"Idle", /* 0x04 */
		"Other" /* 0x07 */
	};
	
	if(code<=0x04)
		return status[code];
	if(code==0x07)
		return status[0x05];
	return out_of_spec;
}

static const char *dmi_processor_upgrade(u8 code)
{
	/* 3.3.5.5 */
	static const char *upgrade[]={
		"Other", /* 0x01 */
		"Unknown",
		"Daughter Board",
		"ZIF Socket",
		"Replaceable Piggy Back",
		"None",
		"LIF Socket",
		"Slot 1",
		"Slot 2",
		"370-pin Socket",
		"Slot A",
		"Slot M",
		"Socket 423",
		"Socket A (Socket 462)",
		"Socket 478",
		"Socket 754",
		"Socket 940" /* 0x11 */
	};
	
	if(code>=0x01 && code<=0x11)
		return upgrade[code-0x01];
	return out_of_spec;
}

static void dmi_processor_cache(u16 code, const char *level, u16 ver)
{
	if(code==0xFFFF)
	{
		if(ver>=0x0203)
			printf(" Not Provided");
		else
			printf(" No %s Cache", level);
	}
	else
		printf(" 0x%04X", code);
}

/*
 * 3.3.6 Memory Controller Information (Type 5)
 */

static const char *dmi_memory_controller_ed_method(u8 code)
{
	/* 3.3.6.1 */
	static const char *method[]={
		"Other", /* 0x01 */
		"Unknown",
		"None",
		"8-bit Parity",
		"32-bit ECC",
		"64-bit ECC",
		"128-bit ECC",
		"CRC" /* 0x08 */
	};
	
	if(code>=0x01 && code<=0x08)
		return(method[code-0x01]);
	return out_of_spec;
}

static void dmi_memory_controller_ec_capabilities(u8 code, const char *prefix)
{
	/* 3.3.6.2 */
	static const char *capabilities[]={
		"Other", /* 0 */
		"Unknown",
		"None",
		"Single-bit Error Correcting",
		"Double-bit Error Correcting",
		"Error Scrubbing" /* 5 */
	};
	
	if((code&0x3F)==0)
		printf(" None\n");
	else
	{
		int i;
		
		printf("\n");
		for(i=0; i<=5; i++)
			if(code&(1<<i))
				printf("%s%s\n", prefix, capabilities[i]);
	}
}

static const char* dmi_memory_controller_interleave(u8 code)
{
	/* 3.3.6.3 */
	static const char *interleave[]={
		"Other", /* 0x01 */
		"Unknown",
		"One-way Interleave",
		"Two-way Interleave",
		"Four-way Interleave",
		"Eight-way Interleave",
		"Sixteen-way Interleave" /* 0x07 */
	};
	
	if(code>=0x01 && code<=0x07)
		return(interleave[code-0x01]);
	return(out_of_spec);
}

static void dmi_memory_controller_speeds(u16 code, const char *prefix)
{
	/* 3.3.6.4 */
	const char *speeds[]={
		"Other", /* 0 */
		"Unknown",
		"70 ns",
		"60 ns",
		"50 ns" /* 4 */
	};
	
	if((code&0x001F)==0)
		printf(" None\n");
	else
	{
		int i;
		
		printf("\n");
		for(i=0; i<=4; i++)
			if(code&(1<<i))
				printf("%s%s\n", prefix, speeds[i]);
	}
}

static void dmi_memory_controller_slots(u8 count, u8 *p, const char *prefix)
{
	int i;
	
	printf("%sAssociated Memory Slots: %u\n",
		prefix, count);
	for(i=0; i<count; i++)
		printf("%s\t0x%04X\n",
			prefix, WORD(p+sizeof(u16)*i));
}

/*
 * 3.3.7 Memory Module Information (Type 6)
 */

static void dmi_memory_module_types(u16 code, const char *sep)
{
	/* 3.3.7.1 */
	static const char *types[]={
		"Other", /* 0 */
		"Unknown",
		"Standard",
		"FPM",
		"EDO",
		"Parity",
		"ECC",
		"SIMM",
		"DIMM",
		"Burst EDO",
		"SDRAM" /* 10 */
	};
	
	if((code&0x03FF)==0)
		printf(" None");
	else
	{
		int i;
		
		for(i=0; i<=10; i++)
			if(code&(1<<i))
				printf("%s%s", sep, types[i]);
	}
}

static void dmi_memory_module_connections(u8 code)
{
	if(code==0xFF)
		printf(" None");
	else
	{
		if((code&0xF0)!=0xF0)
			printf(" %u", code>>4);
		if((code&0x0F)!=0x0F)
			printf(" %u", code&0x0F);
	}
}

static void dmi_memory_module_speed(u8 code)
{
	if(code==0)
		printf(" Unknown");
	else
		printf(" %u ns", code);
}

static void dmi_memory_module_size(u8 code)
{
	/* 3.3.7.2 */
	switch(code&0x7F)
	{
		case 0x7D:
			printf(" Not Determinable");
			break;
		case 0x7E:
			printf(" Disabled");
			break;
		case 0x7F:
			printf(" Not Installed");
			break;
		default:
			printf(" %u MB", 1<<(code&0x7F));
	}
	
	if(code&0x80)
		printf(" (Double-bank Connection)");
	else
		printf(" (Single-bank Connection)");
}

static void dmi_memory_module_error(u8 code, const char *prefix)
{
	if(code&(1<<2))
		printf(" See Event Log\n");
	else
	{	if((code&0x03)==0)
			printf(" OK\n");
		if(code&(1<<0))
			printf("%sUncorrectable Errors\n", prefix);
		if(code&(1<<1))
			printf("%sCorrectable Errors\n", prefix);
	}
}

/*
 * 3.3.8 Cache Information (Type 7)
 */

static const char *dmi_cache_mode(u8 code)
{
	static const char *mode[]={
		"Write Through", /* 0x00 */
		"Write Back",
		"Varies With Memory Address",
		"Unknown" /* 0x03 */
	};
	
	return mode[code];
}

static const char *dmi_cache_location(u8 code)
{
	static const char *location[4]={
		"Internal", /* 0x00 */
		"External",
		NULL, /* 0x02 */
		"Unknown" /* 0x03 */
	};
	
	if(location[code]!=NULL)
		return location[code];
	return out_of_spec;
}

static void dmi_cache_size(u16 code)
{
	if(code&0x8000)
		printf(" %u KB", (code&0x7FFF)<<6);
	else
		printf(" %u KB", code);
}

static void dmi_cache_types(u16 code, const char *sep)
{
	/* 3.3.8.1 */
	static const char *types[]={
		"Other", /* 0 */
		"Unknown",
		"Non-burst",
		"Burst",
		"Pipeline Burst",
		"Synchronous",
		"Asynchronous" /* 6 */
	};
	
	if((code&0x007F)==0)
		printf(" None");
	else
	{
		int i;
		
		for(i=0; i<=6; i++)
			if(code&(1<<i))
				printf("%s%s", sep, types[i]);
	}
}

static const char *dmi_cache_ec_type(u8 code)
{
	/* 3.3.8.2 */
	static const char *type[]={
		"Other", /* 0x01 */
		"Unknown",
		"None",
		"Parity",
		"Single-bit ECC",
		"Multi-bit ECC" /* 0x06 */
	};
	
	if(code>=0x01 && code<=0x06)
		return type[code-0x01];
	return out_of_spec;
}

static const char *dmi_cache_type(u8 code)
{
	/* 3.3.8.3 */
	static const char *type[]={
		"Other", /* 0x01 */
		"Unknown",
		"Instruction",
		"Data",
		"Unified" /* 0x05 */
	};
	
	if(code>=0x01 && code<=0x05)
		return type[code-0x01];
	return out_of_spec;
}

static const char *dmi_cache_associativity(u8 code)
{
	/* 3.3.8.4 */
	static const char *type[]={
		"Other", /* 0x01 */
		"Unknown",
		"Direct Mapped",
		"2-way Set-associative",
		"4-way Set-associative",
		"Fully Associative",
		"8-way Set-associative",
		"16-way Set-associative" /* 0x08 */
	};
	
	if(code>=0x01 && code<=0x08)
		return type[code-0x01];
	return out_of_spec;
}

/*
 * 3.3.9 Port Connector Information (Type 8)
 */

static const char *dmi_port_connector_type(u8 code)
{
	/* 3.3.9.2 */
	static const char *type[]={
		"None", /* 0x00 */
		"Centronics",
		"Mini Centronics",
		"Proprietary",
		"DB-25 male",
		"DB-25 female",
		"DB-15 male",
		"DB-15 female",
		"DB-9 male",
		"DB-9 female",
		"RJ-11", 
		"RJ-45",
		"50 Pin MiniSCSI",
		"Mini DIN",
		"Micro DIN",
		"PS/2",
		"Infrared",
		"HP-HIL",
		"Access Bus (USB)",
		"SSA SCSI",
		"Circular DIN-8 male",
		"Circular DIN-8 female",
		"On Board IDE",
		"On Board Floppy",
		"9 Pin Dual Inline (pin 10 cut)",
		"25 Pin Dual Inline (pin 26 cut)",
		"50 Pin Dual Inline",
		"68 Pin Dual Inline",
		"On Board Sound Input From CD-ROM",
		"Mini Centronics Type-14",
		"Mini Centronics Type-26",
		"Mini Jack (headphones)",
		"BNC",
		"IEEE 1394" /* 0x21 */
	};
	static const char *type_0xA0[]={
		"PC-98", /* 0xA0 */
		"PC-98 Hireso",
		"PC-H98",
		"PC-98 Note",
		"PC-98 Full" /* 0xA4 */
	};
	
	if(code<=0x21)
		return type[code];
	if(code>=0xA0 && code<=0xA4)
		return type_0xA0[code-0xA0];
	if(code==0xFF)
		return "Other";
	return out_of_spec;
}

static const char *dmi_port_type(u8 code)
{
	/* 3.3.9.3 */
	static const char *type[]={
		"None", /* 0x00 */
		"Parallel Port XT/AT Compatible",
		"Parallel Port PS/2",
		"Parallel Port ECP",
		"Parallel Port EPP",
		"Parallel Port ECP/EPP",
		"Serial Port XT/AT Compatible",
		"Serial Port 16450 Compatible",
		"Serial Port 16550 Compatible",
		"Serial Port 16550A Compatible",
		"SCSI Port",
		"MIDI Port",
		"Joystick Port",
		"Keyboard Port",
		"Mouse Port",
		"SSA SCSI",
		"USB",
		"Firewire (IEEE P1394)",
		"PCMCIA Type I",
		"PCMCIA Type II",
		"PCMCIA Type III",
		"Cardbus",
		"Access Bus Port",
		"SCSI II",
		"SCSI Wide",
		"PC-98",
		"PC-98 Hireso",
		"PC-H98",
		"Video Port",
		"Audio Port",
		"Modem Port",
		"Network Port" /* 0x1F */
	};
	static const char *type_0xA0[]={
		"8251 Compatible", /* 0xA0 */
		"8251 FIFO Compatible" /* 0xA1 */
	};
	
	if(code<=0x1F)
		return type[code];
	if(code>=0xA0 && code<=0xA1)
		return type_0xA0[code-0xA0];
	if(code==0xFF)
		return "Other";
	return out_of_spec;
}

/*
 * 3.3.10 System Slots (Type 9)
 */

static const char *dmi_slot_type(u8 code)
{
	/* 3.3.10.1 */
	static const char *type[]={
		"Other", /* 0x01 */
		"Unknown",
		"ISA",
		"MCA",
		"EISA",
		"PCI",
		"PC Card (PCMCIA)",
		"VLB",
		"Proprietary",
		"Processor Card",
		"Proprietary Memory Card",
		"I/O Riser Card",
		"NuBus",
		"PCI-66",
		"AGP",
		"AGP 2x",
		"AGP 4x",
		"PCI-X",
		"AGP 8x" /* 0x13 */
	};
	static const char *type_0xA0[]={
		"PC-98/C20", /* 0xA0 */
		"PC-98/C24",
		"PC-98/E",
		"PC-98/Local Bus",
		"PC-98/Card" /* 0xA4 */
	};
	
	if(code>=0x01 && code<=0x13)
		return type[code-0x01];
	if(code>=0xA0 && code<=0xA4)
		return type_0xA0[code-0xA0];
	return out_of_spec;
}

static const char *dmi_slot_bus_width(u8 code)
{
	/* 3.3.10.2 */
	static const char *width[]={
		"", /* 0x01, "Other" */
		"", /* "Unknown" */
		"8-bit ",
		"16-bit ",
		"32-bit ",
		"64-bit ",
		"128-bit " /* 0x07 */
	};
	
	if(code>=0x01 && code<=0x07)
		return width[code-0x01];
	return out_of_spec;
}

static const char *dmi_slot_current_usage(u8 code)
{
	/* 3.3.10.3 */
	static const char *usage[]={
		"Other", /* 0x01 */
		"Unknown",
		"Available",
		"In Use" /* 0x04 */
	};
	
	if(code>=0x01 && code<=0x04)
		return usage[code-0x01];
	return out_of_spec;
}

static const char *dmi_slot_length(u8 code)
{
	/* 3.3.1O.4 */
	static const char *length[]={
		"Other", /* 0x01 */
		"Unknown",
		"Short",
		"Long" /* 0x04 */
	};
	
	if(code>=0x01 && code<=0x04)
		return length[code-0x01];
	return out_of_spec;
}

static void dmi_slot_id(u8 code1, u8 code2, u8 type, const char *prefix)
{
	/* 3.3.10.5 */
	switch(type)
	{
		case 0x04: /* MCA */
			printf("%sID: %u\n", prefix, code1);
			break;
		case 0x05: /* EISA */
			printf("%sID: %u\n", prefix, code1);
			break;
		case 0x06: /* PCI */
		case 0x0E: /* PCI */
		case 0x0F: /* AGP */
		case 0x10: /* AGP */
		case 0x11: /* AGP */
		case 0x12: /* PCI */
			printf("%sID: %u\n", prefix, code1);
			break;
		case 0x07: /* PCMCIA */
			printf("%sID: Adapter %u, Socket %u\n", prefix, code1, code2);
			break;
	}
}

static void dmi_slot_characteristics(u8 code1, u8 code2, const char *prefix)
{
	/* 3.3.10.6 */
	static const char *characteristics1[]={
		"5.0 V is provided", /* 1 */
		"3.3 V is provided",
		"Opening is shared",
		"PC Card-16 is supported",
		"Cardbus is supported",
		"Zoom Video is supported",
		"Modem ring resume is supported" /* 7 */
	};
	/* 3.3.10.7 */
	static const char *characteristics2[]={
		"PME signal is supported", /* 0 */
		"Hot-plug devices are supported",
		"SMBus signal is supported" /* 2 */
	};
	
	if(code1&(1<<0))
		printf(" Unknown\n");
	else if((code1&0x7F)==0 && (code2&0x07)==0)
		printf(" None\n");
	else
	{
		int i;
		
		printf("\n");
		for(i=1; i<=7; i++)
			if(code1&(1<<i))
				printf("%s%s\n", prefix, characteristics1[i-1]);
		for(i=0; i<=2; i++)
			if(code2&(1<<i))
				printf("%s%s\n", prefix, characteristics2[i]);
	}
}

/*
 * 3.3.11 On Board Devices Information (Type 10)
 */

static const char *dmi_on_board_devices_type(u8 code)
{
	/* 3.3.11.1 */
	static const char *type[]={
		"Other", /* 0x01 */
		"Unknown",
		"Video",
		"SCSI Controller",
		"Ethernet",
		"Token Ring",
		"Sound" /* 0x07 */
	};
	
	if(code>=0x01 && code <=0x07)
		return type[code-0x01];
	return out_of_spec;
}

static void dmi_on_board_devices(struct dmi_header *h, const char *prefix)
{
	u8 *p=(u8 *)h+4;
	u8 count=(h->length-0x04)/2;
	int i;

	for(i=0; i<count; i++)
	{
		printf("%sOn Board Device Information\n",
			prefix);
		printf("%s\tType: %s\n",
			prefix, dmi_on_board_devices_type(p[2*i]&0x7F));
		printf("%s\tStatus: %s\n",
			prefix, p[2*i]&0x80?"Enabled":"Disabled");
		printf("%s\tDescription: %s\n",
			prefix, dmi_string(h, p[2*i+1]));
	}
}

/*
 * 3.3.12 OEM Strings (Type 11)
 */

static void dmi_oem_strings(struct dmi_header *h, const char *prefix)
{
	u8 *p=(u8 *)h+4;
	u8 count=p[0x00];
	int i;
	
	for(i=1; i<=count; i++)
		printf("%sString %d: %s\n",
			prefix, i, dmi_string(h, i));
}

/*
 * 3.3.13 System Configuration Options (Type 12)
 */

static void dmi_system_configuration_options(struct dmi_header *h, const char *prefix)
{
	u8 *p=(u8 *)h+4;
	u8 count=p[0x00];
	int i;
	
	for(i=1; i<=count; i++)
		printf("%sOption %d: %s\n",
			prefix, i, dmi_string(h, i));
}

/*
 * 3.3.14 BIOS Language Information (Type 13)
 */

static void dmi_bios_languages(struct dmi_header *h, const char *prefix)
{
	u8 *p=(u8 *)h+4;
	u8 count=p[0x00];
	int i;
	
	for(i=1; i<=count; i++)
		printf("%s%s\n",
			prefix, dmi_string(h, i));
}

/*
 * 3.3.15 Group Associations (Type 14)
 */

static void dmi_group_associations_items(u8 count, u8 *p, const char *prefix)
{
	int i;
	
	for(i=0; i<count; i++)
	{
		printf("%s0x%04X (%s)\n",
			prefix, WORD(p+3*i+1),
			dmi_smbios_structure_type(p[3*i]));
	}
}

/*
 * 3.3.16 System Event Log (Type 15)
 */

static const char *dmi_event_log_method(u8 code)
{
	static const char *method[]={
		"Indexed I/O, one 8-bit index port, one 8-bit data port", /* 0x00 */
		"Indexed I/O, two 8-bit index ports, one 8-bit data port",
		"Indexed I/O, one 16-bit index port, one 8-bit data port",
		"Memory-mapped physical 32-bit address",
		"General-purpose non-volatile data functions" /* 0x04 */
	};
	
	if(code<=0x04)
		return method[code];
	if(code>=0x80)
		return "OEM-specific";
	return out_of_spec;
}

static void dmi_event_log_status(u8 code)
{
	static const char *valid[]={
		"Invalid", /* 0 */
		"Valid" /* 1 */
	};
	static const char *full[]={
		"Not Full", /* 0 */
		"Full" /* 1 */
	};
	
	printf(" %s, %s",
		valid[code&(1<<0)], full[code&(1<<1)]);
}

static void dmi_event_log_address(u8 method, u8 *p)
{
	/* 3.3.16.3 */
	switch(method)
	{
		case 0x00:
		case 0x01:
		case 0x02:
			printf(" Index 0x%04X, Data 0x%04X", WORD(p), WORD(p+2));
			break;
		case 0x03:
			printf(" 0x%08X", DWORD(p));
			break;
		case 0x04:
			printf(" 0x%04X", WORD(p));
			break;
		default:
			printf(" Unknown");
	}
}

static const char *dmi_event_log_header_type(u8 code)
{
	static const char *type[]={
		"No Header", /* 0x00 */
		"Type 1" /* 0x01 */
	};
	
	if(code<=0x01)
		return type[code];
	if(code>=0x80)
		return "OEM-specific";
	return out_of_spec;
}

static const char *dmi_event_log_descriptor_type(u8 code)
{
	/* 3.3.16.6.1 */
	static const char *type[]={
		NULL, /* 0x00 */
		"Single-bit ECC memory error",
		"Multi-bit ECC memory error",
		"Parity memory error",
		"Bus timeout",
		"I/O channel block",
		"Software NMI",
		"POST memory resize",
		"POST error",
		"PCI parity error",
		"PCI system error",
		"CPU failure",
		"EISA failsafe timer timeout",
		"Correctable memory log disabled",
		"Logging disabled",
		NULL, /* 0x0F */
		"System limit exceeded",
		"Asynchronous hardware timer expired",
		"System configuration information",
		"Hard disk information",
		"System reconfigured",
		"Uncorrectable CPU-complex error",
		"Log area reset/cleared",
		"System boot" /* 0x17 */
	};
	
	if(code<=0x17 && type[code]!=NULL)
		return type[code];
	if(code>=0x80 && code<=0xFE)
		return "OEM-specific";
	if(code==0xFF)
		return "End of log";
	return out_of_spec;
}

static const char *dmi_event_log_descriptor_format(u8 code)
{
	/* 3.3.16.6.2 */
	static const char *format[]={
		"None", /* 0x00 */
		"Handle",
		"Multiple-event",
		"Multiple-event handle",
		"POST results bitmap",
		"System management",
		"Multiple-event system management" /* 0x06 */
	};
	
	if(code<=0x06)
		return format[code];
	if(code>=0x80)
		return "OEM-specific";
	return out_of_spec;
}

static void dmi_event_log_descriptors(u8 count, u8 len, u8 *p, const char *prefix)
{
	/* 3.3.16.1, , 3.3.16.6.2 */
	int i;
	
	for(i=0; i<count; i++)
	{
		if(len>=0x02)
		{
			printf("%sDescriptor %u: %s\n",
				prefix, i+1, dmi_event_log_descriptor_type(p[i*len]));
			printf("%sData Format %u: %s\n",
				prefix, i+1, dmi_event_log_descriptor_format(p[i*len+1]));
		}
	}
}

/*
 * 3.3.17 Physical Memory Array (Type 16)
 */

static const char *dmi_memory_array_location(u8 code)
{
	/* 3.3.17.1 */
	static const char *location[]={
		"Other", /* 0x01 */
		"Unknown",
		"System Board Or Motherboard",
		"ISA Add-on Card",
		"EISA Add-on Card",
		"PCI Add-on Card",
		"MCA Add-on Card",
		"PCMCIA Add-on Card",
		"Proprietary Add-on Card",
		"NuBus" /* 0x0A, master.mif says 16 */
	};
	static const char *location_0xA0[]={
		"PC-98/C20 Add-on Card", /* 0xA0 */
		"PC-98/C24 Add-on Card",
		"PC-98/E Add-on Card",
		"PC-98/Local Bus Add-on Card",
		"PC-98/Card Slot Add-on Card" /* 0xA4, from master.mif */
	};
	
	if(code>=0x01 && code<=0x0A)
		return location[code-0x01];
	if(code>=0xA0 && code<=0xA4)
		return location_0xA0[code-0xA0];
	return out_of_spec;
}

static const char *dmi_memory_array_use(u8 code)
{
	/* 3.3.17.2 */
	static const char *use[]={
		"Other", /* 0x01 */
		"Unknown",
		"System Memory",
		"Video Memory",
		"Flash Memory",
		"Non-volatile RAM",
		"Cache Memory" /* 0x07 */
	};
	
	if(code>=0x01 && code<=0x07)
		return use[code-0x01];
	return out_of_spec;
}

static const char *dmi_memory_array_ec_type(u8 code)
{
	/* 3.3.17.3 */
	static const char *type[]={
		"Other", /* 0x01 */
		"Unknown",
		"None",
		"Parity",
		"Single-bit ECC",
		"Multi-bit ECC",
		"CRC" /* 0x07 */
	};
	
	if(code>=0x01 && code<=0x07)
		return type[code-0x01];
	return out_of_spec;
}

static void dmi_memory_array_capacity(u32 code)
{
	if(code==0x8000000)
		printf(" Unknown");
	else
	{
		if((code&0x000FFFFF)==0)
			printf(" %u GB", code>>20);
		else if((code&0x000003FF)==0)
			printf(" %u MB", code>>10);
		else
			printf(" %u kB", code);
	}
}

static void dmi_memory_array_error_handle(u16 code)
{
	if(code==0xFFFE)
		printf(" Not Provided");
	else if(code==0xFFFF)
		printf(" No Error");
	else
		printf(" 0x%04X", code);
}

/*
 * 3.3.18 Memory Device (Type 17)
 */

static void dmi_memory_device_width(u16 code)
{
	/*
	 * If no memory module is present, width may be 0
	 */
	if(code==0xFFFF || code==0)
		printf(" Unknown");
	else
		printf(" %u bits", code);
}

static void dmi_memory_device_size(u16 code)
{
	if(code==0)
		printf(" No Module Installed");
	else if(code==0xFFFF)
		printf(" Unknown");
	else
	{
		if(code&0x8000)
			printf(" %u kB", code&0x7FFF);
		else
			printf(" %u MB", code);
	}
}

static const char *dmi_memory_device_form_factor(u8 code)
{
	/* 3.3.18.1 */
	static const char *form_factor[]={
		"Other", /* 0x01 */
		"Unknown",
		"SIMM",
		"SIP",
		"Chip",
		"DIP",
		"ZIP",
		"Proprietary Card",
		"DIMM",
		"TSOP",
		"Row Of Chips",
		"RIMM",
		"SODIMM",
		"SRIMM" /* 0x0E */
	};
	
	if(code>=0x01 && code<=0x0E)
		return form_factor[code-0x01];
	return out_of_spec;
}

static void dmi_memory_device_set(u8 code)
{
	if(code==0)
		printf(" None");
	else if(code==0xFF)
		printf(" Unknown");
	else
		printf(" %u", code);
}

static const char *dmi_memory_device_type(u8 code)
{
	/* 3.3.18.2 */
	static const char *type[]={
		"Other", /* 0x01 */
		"Unknown",
		"DRAM",
		"EDRAM",
		"VRAM",
		"SRAM",
		"RAM",
		"ROM",
		"Flash",
		"EEPROM",
		"FEPROM",
		"EPROM",
		"CDRAM",
		"3DRAM",
		"SDRAM",
		"SGRAM",
		"RDRAM",
		"DDR" /* 0x12 */
	};
	
	if(code>=0x01 && code<=0x12)
		return type[code-0x01];
	return out_of_spec;
}

static void dmi_memory_device_type_detail(u16 code)
{
	/* 3.3.18.3 */
	static const char *detail[]={
		"Other", /* 1 */
		"Unknown",
		"Fast-paged",
		"Static Column",
		"Pseudo-static",
		"RAMBus",
		"Synchronous",
		"CMOS",
		"EDO",
		"Window DRAM",
		"Cache DRAM",
		"Non-Volatile" /* 12 */
	};
	
	if((code&0x1FFE)==0)
		printf(" None");
	else
	{
		int i;
		
		for(i=1; i<=12; i++)
			if(code&(1<<i))
				printf(" %s", detail[i-1]);
	}
}

static void dmi_memory_device_speed(u16 code)
{
	if(code==0)
		printf(" Unknown");
	else
		printf(" %u MHz (%.1f ns)", code, (float)1000/code);
}

/*
 * 3.3.19 32-bit Memory Error Information (Type 18)
 */

static const char *dmi_memory_error_type(u8 code)
{
	/* 3.3.19.1 */
	static const char *type[]={
		"Other", /* 0x01 */
		"Unknown",
		"OK"
		"Bad Read",
		"Parity Error",
		"Single-bit Error",
		"Double-bit Error",
		"Multi-bit Error",
		"Nibble Error",
		"Checksum Error",
		"CRC Error",
		"Corrected Single-bit Error",
		"Corrected Error",
		"Uncorrectable Error" /* 0x0E */
	};
	
	if(code>=0x01 && code<=0x0E)
		return type[code-0x01];
	return out_of_spec;
}

static const char *dmi_memory_error_granularity(u8 code)
{
	/* 3.3.19.2 */
	static const char *granularity[]={
		"Other", /* 0x01 */
		"Unknown",
		"Device Level",
		"Memory Partition Level" /* 0x04 */
	};
	
	if(code>=0x01 && code<=0x04)
		return granularity[code-0x01];
	return out_of_spec;
}

static const char *dmi_memory_error_operation(u8 code)
{
	/* 3.3.19.3 */
	static const char *operation[]={
		"Other", /* 0x01 */
		"Unknown",
		"Read",
		"Write",
		"Partial Write" /* 0x05 */
	};
	
	if(code>=0x01 && code<=0x05)
		return operation[code-0x01];
	return out_of_spec;
}

static void dmi_memory_error_syndrome(u32 code)
{
	if(code==0x00000000)
		printf(" Unknown");
	else
		printf(" 0x%08X", code);
}

static void dmi_32bit_memory_error_address(u32 code)
{
	if(code==0x80000000)
		printf(" Unknown");
	else
		printf(" 0x%08X", code);
}

/*
 * 3.3.20 Memory Array Mapped Address (Type 19)
 */

static void dmi_mapped_address_size(u32 code)
{
	if(code==0)
		printf(" Invalid");
	else if((code&0x000FFFFF)==0)
		printf(" %u GB", code>>20);
	else if((code&0x000003FF)==0)
		printf(" %u MB", code>>10);
	else
		printf(" %u kB", code);
}

/*
 * 3.3.21 Memory Device Mapped Address (Type 20)
 */

static void dmi_mapped_address_row_position(u8 code)
{
	if(code==0)
		printf(" %s", out_of_spec);
	else if(code==0xFF)
		printf(" Unknown");
	else
		printf(" %u", code);
}

static void dmi_mapped_address_interleave_position(u8 code, const char *prefix)
{
	if(code!=0)
	{
		printf("%sInterleave Position:", prefix);
		if(code==0xFF)
			printf(" Unknown");
		else
			printf(" %u", code);
		printf("\n");
	}
}

static void dmi_mapped_address_interleaved_data_depth(u8 code, const char *prefix)
{
	if(code!=0)
	{
		printf("%sInterleaved Data Depth:", prefix);
		if(code==0xFF)
			printf(" Unknown");
		else
			printf(" %u", code);
		printf("\n");
	}
}

/*
 * 3.3.22 Built-in Pointing Device (Type 21)
 */

static const char *dmi_pointing_device_type(u8 code)
{
	/* 3.3.22.1 */
	static const char *type[]={
		"Other", /* 0x01 */
		"Unknown",
		"Mouse",
		"Track Ball",
		"Track Point",
		"Glide Point",
		"Touch Pad",
		"Touch Screen",
		"Optical Sensor" /* 0x09 */
	};
	
	if(code>=0x01 && code<=0x09)
		return type[code-0x01];
	return out_of_spec;
}

static const char *dmi_pointing_device_interface(u8 code)
{
	/* 3.3.22.2 */
	static const char *interface[]={
		"Other", /* 0x01 */
		"Unknown",
		"Serial",
		"PS/2",
		"Infrared",
		"HIP-HIL",
		"Bus Mouse",
		"ADB (Apple Desktop Bus)" /* 0x08 */
	};
	static const char *interface_0xA0[]={
		"Bus Mouse DB-9", /* 0xA0 */
		"Bus Mouse Micro DIN",
		"USB" /* 0xA2 */
	};
	
	if(code>=0x01 && code<=0x08)
		return interface[code-0x01];
	if(code>=0xA0 && code<=0xA2)
		return interface_0xA0[code-0xA0];
	return out_of_spec;
}

/*
 * 3.3.23 Portable Battery (Type 22)
 */
 
static const char *dmi_battery_chemistry(u8 code)
{
	/* 3.3.23.1 */
	static const char *chemistry[]={
		"Other", /* 0x01 */
		"Unknown",
		"Lead Acid",
		"Nickel Cadmium",
		"Nickel Metal Hydride",
		"Lithium Ion",
		"Zinc Air",
		"Lithium Polymer" /* 0x08 */
	};

	if(code>=0x01 && code<=0x08)
		return chemistry[code-0x01];
	return out_of_spec;
}

static void dmi_battery_capacity(u16 code, u8 multiplier)
{
	if(code==0)
		printf(" Unknown");
	else
		printf(" %u mWh", code*multiplier);
}

static void dmi_battery_voltage(u16 code)
{
	if(code==0)
		printf(" Unknown");
	else
		printf(" %u mV", code);
}

static void dmi_battery_maximum_error(u8 code)
{
	if(code==0xFF)
		printf(" Unknown");
	else
		printf(" %u%%", code);
}

/*
 * 3.3.24 System Reset (Type 23)
 */

static const char *dmi_system_reset_boot_option(u8 code)
{
	static const char *option[]={
		"Operating System", /* 0x1 */
		"System Utilities",
		"Do Not Reboot" /* 0x3 */
	};
	
	if(code>=0x1)
		return option[code-0x1];
	return out_of_spec;
}

static void dmi_system_reset_count(u16 code)
{
	if(code==0xFFFF)
		printf(" Unknown");
	else
		printf(" %u", code);
}

static void dmi_system_reset_timer(u16 code)
{
	if(code==0xFFFF)
		printf(" Unknown");
	else
		printf(" %u min", code);
}

/*
 * 3.3.25 Hardware Security (Type 24)
 */

static const char *dmi_hardware_security_status(u8 code)
{
	static const char *status[]={
		"Disabled", /* 0x00 */
		"Enabled",
		"Not Implemented",
		"Unknown" /* 0x03 */
	};
	
	return status[code];
}

/*
 * 3.3.26 System Power Controls (Type 25)
 */

static void dmi_power_controls_power_on(u8 *p)
{
	/* 3.3.26.1 */
	if(dmi_bcd_range(p[0], 0x01, 0x12))
		printf(" %02X", p[0]);
	else
		printf(" *");
	if(dmi_bcd_range(p[1], 0x01, 0x31))
		printf("-%02X", p[1]);
	else
		printf("-*");
	if(dmi_bcd_range(p[2], 0x00, 0x23))
		printf(" %02X", p[2]);
	else
		printf(" *");
	if(dmi_bcd_range(p[3], 0x00, 0x59))
		printf(":%02X", p[3]);
	else
		printf(":*");
	if(dmi_bcd_range(p[4], 0x00, 0x59))
		printf(":%02X", p[4]);
	else
		printf(":*");
}

/*
 * 3.3.27 Voltage Probe (Type 26)
 */

static const char *dmi_voltage_probe_location(u8 code)
{
	/* 3.3.27.1 */
	static const char *location[]={
		"Other", /* 0x01 */
		"Unknown",
		"Processor",
		"Disk",
		"Peripheral Bay",
		"System Management Module",
		"Motherboard",
		"Memory Module",
		"Processor Module",
		"Power Unit",
		"Add-in Card" /* 0x0B */
	};
	
	if(code>=0x01 && code<=0x0B)
		return location[code-0x01];
	return out_of_spec;
}

static const char *dmi_probe_status(u8 code)
{
	/* 3.3.27.1 */
	static const char *status[]={
		"Other", /* 0x01 */
		"Unknown",
		"OK",
		"Non-critical",
		"Critical",
		"Non-recoverable" /* 0x06 */
	};
	
	if(code>=0x01 && code<=0x06)
		return status[code-0x01];
	return out_of_spec;
}

static void dmi_voltage_probe_value(u16 code)
{
	if(code==0x8000)
		printf(" Unknown");
	else
		printf(" %.3f V", (float)(i16)code/1000);
}

static void dmi_voltage_probe_resolution(u16 code)
{
	if(code==0x8000)
		printf(" Unknown");
	else
		printf(" %.1f mV", (float)code/10);
}

static void dmi_probe_accuracy(u16 code)
{
	if(code==0x8000)
		printf(" Unknown");
	else
		printf(" %.2f%%", (float)code/100);
}

/*
 * 3.3.28 Cooling Device (Type 27)
 */

static const char *dmi_cooling_device_type(u8 code)
{
	/* 3.3.28.1 */
	static const char *type[]={
		"Other", /* 0x01 */
		"Unknown",
		"Fan",
		"Centrifugal Blower",
		"Chip Fan",
		"Cabinet Fan",
		"Power Supply Fan",
		"Heat Pipe",
		"Integrated Refrigeration" /* 0x09 */
	};
	static const char *type_0x10[]={
		"Active Cooling", /* 0x10, master.mif says 32 */
		"Passive Cooling" /* 0x11, master.mif says 33 */
	};
	
	if(code>=0x01 && code<=0x09)
		return type[code-0x01];
	if(code>=0x10 && code<=0x11)
		return type_0x10[code-0x10];
	return out_of_spec;
}

static void dmi_cooling_device_speed(u16 code)
{
	if(code==0x8000)
		printf(" Unknown Or Non-rotating");
	else
		printf(" %u rpm", code);
}

/*
 * 3.3.29 Temperature Probe (Type 28)
 */

static const char *dmi_temperature_probe_location(u8 code)
{
	/* 3.3.29.1 */
	static const char *location[]={
		"Other", /* 0x01 */
		"Unknown",
		"Processor",
		"Disk",
		"Peripheral Bay",
		"System Management Module", /* master.mif says SMB MAster */
		"Motherboard",
		"Memory Module",
		"Processor Module",
		"Power Unit",
		"Add-in Card",
		"Front Panel Board",
		"Back Panel Board",
		"Power System Board",
		"Drive Back Plane" /* 0x0F */
	};
	
	if(code>=0x01 && code<=0x0F)
		return location[code-0x01];
	return out_of_spec;
}

static void dmi_temperature_probe_value(u16 code)
{
	if(code==0x8000)
		printf(" Unknown");
	else
		printf(" %.1f deg C", (float)(i16)code/10);
}

static void dmi_temperature_probe_resolution(u16 code)
{
	if(code==0x8000)
		printf(" Unknown");
	else
		printf(" %.3f deg C", (float)code/1000);
}

/*
 * 3.3.30 Electrical Current Probe (Type 29)
 */

static void dmi_current_probe_value(u16 code)
{
	if(code==0x8000)
		printf(" Unknown");
	else
		printf(" %.3f A", (float)(i16)code/1000);
}

static void dmi_current_probe_resolution(u16 code)
{
	if(code==0x8000)
		printf(" Unknown");
	else
		printf(" %.1f mA", (float)code/10);
}

/*
 * 3.3.33 System Boot Information (Type 32)
 */

static const char *dmi_system_boot_status(u8 code)
{
	static const char *status[]={
		"No errors detected", /* 0 */
		"No bootable media",
		"Operating system failed to load",
		"Firmware-detected hardware failure",
		"Operating system-detected hardware failure",
		"User-requested boot",
		"System security violation",
		"Previously-requested image",
		"System watchdog timer expired" /* 8 */
	};
	
	if(code<=8)
		return status[code];
	if(code>=128 && code<=191)
		return "OEM-specific";
	if(code>=192)
		return "Product-specific";
	return out_of_spec;
}

/*
 * 3.3.34 64-bit Memory Error Information (Type 33)
 */

static void dmi_64bit_memory_error_address(u64 code)
{
	if(code.h==0x80000000 && code.l==0x00000000)
		printf(" Unknown");
	else
		printf(" 0x%08X%08X", code.h, code.l);
}

/*
 * 3.3.35 Management Device (Type 34)
 */

static const char *dmi_management_device_type(u8 code)
{
	/* 3.3.35.1 */
	static const char *type[]={
		"Other", /* 0x01 */
		"Unknown",
		"LM75",
		"LM78",
		"LM79",
		"LM80",
		"LM81",
		"ADM9240",
		"DS1780",
		"MAX1617",
		"GL518SM",
		"W83781D",
		"HT82H791" /* 0x0D */
	};
	
	if(code>=0x01 && code<=0x0D)
		return type[code-0x01];
	return out_of_spec;
}

static const char *dmi_management_device_address_type(u8 code)
{
	/* 3.3.35.2 */
	static const char *type[]={
		"Other", /* 0x01 */
		"Unknown",
		"I/O Port",
		"Memory",
		"SMBus" /* 0x05 */
	};
	
	if(code>=0x01 && code<=0x05)
		return type[code-0x01];
	return out_of_spec;
}

/*
 * 3.3.38 Memory Channel (Type 37)
 */

static const char *dmi_memory_channel_type(u8 code)
{
	/* 3.3.38.1 */
	static const char *type[]={
		"Other", /* 0x01 */
		"Unknown",
		"RAMBus",
		"Synclink" /* 0x04 */
	};
	
	if(code>=0x01 && code<=0x04)
		return type[code-0x01];
	return out_of_spec;
}

static void dmi_memory_channel_devices(u8 count, u8 *p, const char *prefix)
{
	int i;
	
	for(i=1; i<=count; i++)
	{
		printf("%sDevice %u Load: %u\n",
			prefix, i, p[3*i]);
		printf("%sDevice %u Handle: 0x%04X\n",
			prefix, i, WORD(p+3*i+1));
	}
}

/*
 * 3.3.39 IPMI Device Information (Type 38)
 */

static const char *dmi_ipmi_interface_type(u8 code)
{
	/* 3.3.39.1 */
	static const char *type[]={
		"Unknown", /* 0x00 */
		"KCS (Keyboard Control Style)",
		"SMIC (Server Management Interface Chip)",
		"BT (Block Transfer)" /* 0x03 */
	};
	
	if(code<=0x03)
		return type[code];
	return out_of_spec;
}

static const char *dmi_ipmi_register_spacing(u8 code)
{
	/* IPMI 1.5 */
	static const char *spacing[]={
		"Successive Byte Boundaries", /* 0x00 */
		"32-bit Boundaries",
		"16-byte Boundaries" /* 0x02 */
	};
	
	if(code<=0x02)
		return spacing[code];
	return out_of_spec;
}

/*
 * 3.3.40 System Power Supply (Type 39)
 */

static void dmi_power_supply_power(u16 code)
{
	if(code==0x8000)
		printf(" Unknown");
	else
		printf(" %.3f W", (float)code/1000);
}

static const char *dmi_power_supply_type(u8 code)
{
	/* 3.3.40.1 */
	static const char *type[]={
		"Other", /* 0x01 */
		"Unknown",
		"Linear",
		"Switching",
		"Battery",
		"UPS",
		"Converter",
		"Regulator" /* 0x08 */
	};
	
	if(code>=0x01 && code<=0x08)
		return type[code-0x01];
	return out_of_spec;
}

static const char *dmi_power_supply_status(u8 code)
{
	/* 3.3.40.1 */
	static const char *status[]={
		"Other", /* 0x01 */
		"Unknown",
		"OK",
		"Non-critical"
		"Critical" /* 0x05 */
	};
	
	if(code>=0x01 && code<=0x05)
		return status[code-0x01];
	return out_of_spec;
}

static const char *dmi_power_supply_range_switching(u8 code)
{
	/* 3.3.40.1 */
	static const char *switching[]={
		"Other", /* 0x01 */
		"Unknown",
		"Manual",
		"Auto-switch",
		"Wide Range",
		"N/A" /* 0x06 */
	};
	
	if(code>=0x01 && code<=0x06)
		return switching[code-0x01];
	return out_of_spec;
}

/*
 * Main
 */

static void dmi_decode(u8 *data, u16 ver)
{
	struct dmi_header *h=(struct dmi_header *)data;
	
	/*
	 * Note: DMI types 31, 37, 38 and 39 are untested
	 */
	switch(h->type)
	{
		case 0: /* 3.3.1 BIOS Information */
			printf("\tBIOS Information\n");
			if(h->length<0x12) break;
			printf("\t\tVendor: %s\n", 
				dmi_string(h, data[0x04]));
			printf("\t\tVersion: %s\n", 
				dmi_string(h, data[0x05]));
			printf("\t\tRelease Date: %s\n",
				dmi_string(h, data[0x08]));
			printf("\t\tAddress: 0x%04X0\n",
				WORD(data+0x06));
			printf("\t\tRuntime Size:");
			dmi_bios_runtime_size((0x10000-WORD(data+0x06))<<4);
			printf("\n");
			printf("\t\tROM Size: %u kB\n",
				(data[0x09]+1)<<6);
			printf("\t\tCharacteristics:\n");
			dmi_bios_characteristics(QWORD(data+0x0A), "\t\t\t");
			if(h->length<0x13) break;
			dmi_bios_characteristics_x1(data[0x12], "\t\t\t");
			if(h->length<0x14) break;
			dmi_bios_characteristics_x2(data[0x13], "\t\t\t");
			break;
		
		case 1: /* 3.3.2 System Information */
			printf("\tSystem Information\n");
			if(h->length<0x08) break;
			printf("\t\tManufacturer: %s\n",
				dmi_string(h, data[0x04]));
			printf("\t\tProduct Name: %s\n",
				dmi_string(h, data[0x05]));
			printf("\t\tVersion: %s\n",
				dmi_string(h, data[0x06]));
			printf("\t\tSerial Number: %s\n",
				dmi_string(h, data[0x07]));
			if(h->length<0x19) break;
			printf("\t\tUUID:");
			dmi_system_uuid(data+0x08);
			printf("\n");
			printf("\t\tWake-up Type: %s\n",
				dmi_system_wake_up_type(data[0x18]));
			break;
		
		case 2: /* 3.3.3 Base Board Information */
			printf("\tBase Board Information\n");
			if(h->length<0x08) break;
			printf("\t\tManufacturer: %s\n",
				dmi_string(h, data[0x04]));
			printf("\t\tProduct Name: %s\n",
				dmi_string(h, data[0x05]));
			printf("\t\tVersion: %s\n",
				dmi_string(h, data[0x06]));
			printf("\t\tSerial Number: %s\n",
				dmi_string(h, data[0x07]));
			if(h->length<0x0F) break;
			printf("\t\tAsset Tag: %s\n",
				dmi_string(h, data[0x08]));
			printf("\t\tFeatures:");
			dmi_base_board_features(data[0x09], "\t\t");
			printf("\t\tLocation In Chassis: %s\n",
				dmi_string(h, data[0x0A]));
			printf("\t\tChassis Handle: 0x%04X\n",
				WORD(data+0x0B));
			printf("\t\tType: %s\n",
				dmi_base_board_type(data[0x0D]));
			if(h->length<0x0F+data[0x0E]*sizeof(u16)) break;
			dmi_base_board_handlers(data[0x0E], data+0x0F, "\t\t");
			break;
		
		case 3: /* 3.3.4 Chassis Information */
			printf("\tChassis Information\n");
			if(h->length<0x09) break;
			printf("\t\tManufacturer: %s\n",
				dmi_string(h, data[0x04]));
			printf("\t\tType: %s\n",
				dmi_chassis_type(data[0x05]&0x7F));
			printf("\t\tLock: %s\n",
				dmi_chassis_lock(data[0x05]>>7));
			printf("\t\tVersion: %s\n",
				dmi_string(h, data[0x06]));
			printf("\t\tSerial Number: %s\n",
				dmi_string(h, data[0x07]));
			printf("\t\tAsset Tag: %s\n",
				dmi_string(h, data[0x08]));
			if(h->length<0x0D) break;
			printf("\t\tBoot-up State: %s\n",
				dmi_chassis_state(data[0x09]));
			printf("\t\tPower Supply State: %s\n",
				dmi_chassis_state(data[0x0A]));
			printf("\t\tThermal State: %s\n",
				dmi_chassis_state(data[0x0B]));
			printf("\t\tSecurity Status: %s\n",
				dmi_chassis_security_status(data[0x0C]));
			if(h->length<0x11) break;
			printf("\t\tOEM Information: 0x%08X\n",
				DWORD(data+0x0D));
			if(h->length<0x15) break;
			printf("Heigth:");
			dmi_chassis_height(data[0x11]);
			printf("\n");
			printf("Number Of Power Cords:");
			dmi_chassis_power_cords(data[0x12]);
			printf("\n");
			if(h->length<0x15+data[0x13]*data[0x14]) break;
			dmi_chassis_elements(data[0x13], data[0x14], data+0x15, "\t\t");
			break;
		
		case 4: /* 3.3.5 Processor Information */
			printf("\tProcessor Information\n");
			if(h->length<0x1A) break;
			printf("\t\tSocket Designation: %s\n",
				dmi_string(h, data[0x04]));
			printf("\t\tType: %s\n",
				dmi_processor_type(data[0x05]));
			printf("\t\tFamily: %s\n",
				dmi_processor_family(data[0x06]));
			printf("\t\tManufacturer: %s\n",
				dmi_string(h, data[0x07]));
			dmi_processor_id(data[0x06], data+8, dmi_string(h, data[0x10]), "\t\t");
			printf("\t\tVersion: %s\n",
				dmi_string(h, data[0x10]));
			printf("\t\tVoltage:");
			dmi_processor_voltage(data[0x11]);
			printf("\n");
			printf("\t\tExternal Clock:");
			dmi_processor_frequency(WORD(data+0x12));
			printf("\n");
			printf("\t\tMax Speed:");
			dmi_processor_frequency(WORD(data+0x14));
			printf("\n");
			printf("\t\tCurrent Speed:");
			dmi_processor_frequency(WORD(data+0x16));
			printf("\n");
			if(data[0x18]&(1<<6))
				printf("\t\tStatus: Populated, %s\n",
					dmi_processor_status(data[0x18]&0x07));
			else
				printf("\t\tStatus: Unpopulated\n");
			printf("\t\tUpgrade: %s\n",
				dmi_processor_upgrade(data[0x19]));
			if(h->length<0x20) break;
			printf("\t\tL1 Cache Handle:");
			dmi_processor_cache(WORD(data+0x1A), "L1", ver);
			printf("\n");
			printf("\t\tL2 Cache Handle:");
			dmi_processor_cache(WORD(data+0x1C), "L2", ver);
			printf("\n");
			printf("\t\tL3 Cache Handle:");
			dmi_processor_cache(WORD(data+0x1E), "L3", ver);
			printf("\n");
			if(h->length<0x23) break;
			printf("\t\tSerial Number: %s\n",
				dmi_string(h, data[0x20]));
			printf("\t\tAsset Tag: %s\n",
				dmi_string(h, data[0x21]));
			printf("\t\tPart Number: %s\n",
				dmi_string(h, data[0x22]));
			break;
		
		case 5: /* 3.3.6 Memory Controller Information */
			printf("\tMemory Controller Information\n");
			if(h->length<0x0F) break;
			printf("\t\tError Detecting Method: %s\n",
				dmi_memory_controller_ed_method(data[0x04]));
			printf("\t\tError Correcting Capabilities:");
			dmi_memory_controller_ec_capabilities(data[0x05], "\t\t\t");
			printf("\t\tSupported Interleave: %s\n",
				dmi_memory_controller_interleave(data[0x06]));
			printf("\t\tCurrent Interleave: %s\n",
				dmi_memory_controller_interleave(data[0x07]));
			printf("\t\tMaximum Memory Module Size: %u MB\n",
				1<<data[0x08]);
			printf("\t\tMaximum Total Memory Size: %u MB\n",
				data[0x0E]*(1<<data[0x08]));
			printf("\t\tSupported Speeds:");
			dmi_memory_controller_speeds(WORD(data+0x09), "\t\t\t");
			printf("\t\tSupported Memory Types:");
			dmi_memory_module_types(WORD(data+0x0B), "\n\t\t\t");
			printf("\n");
			printf("\t\tMemory Module Voltage:");
			dmi_processor_voltage(data[0x0D]);
			printf("\n");
			if(h->length<0x0F+data[0x0E]*sizeof(u16)) break;
			dmi_memory_controller_slots(data[0x0E], data+0x0F, "\t\t");
			if(h->length<0x10+data[0x0E]*sizeof(u16)) break;
			printf("\t\tEnabled Error Correcting Capabilities:");
			dmi_memory_controller_ec_capabilities(data[0x0F+data[0x0E]*sizeof(u16)], "\t\t\t");
			break;
		
		case 6: /* 3.3.7 Memory Module Information */
			printf("\tMemory Module Information\n");
			if(h->length<0x0C) break;
			printf("\t\tSocket Designation: %s\n",
				dmi_string(h, data[0x04]));
			printf("\t\tBank Connections:");
			dmi_memory_module_connections(data[0x05]);
			printf("\n");
			printf("\t\tCurrent Speed:");
			dmi_memory_module_speed(data[0x06]);
			printf("\n");
			printf("\t\tType:");
			dmi_memory_module_types(WORD(data+0x07), " ");
			printf("\n");
			printf("\t\tInstalled Size:");
			dmi_memory_module_size(data[0x09]);
			printf("\n");
			printf("\t\tEnabled Size:");
			dmi_memory_module_size(data[0x0A]);
			printf("\n");
			printf("\t\tError Status:");
			dmi_memory_module_error(data[0x0B], "\t\t\t");
			break;
		
		case 7: /* 3.3.8 Cache Information */
			printf("\tCache Information\n");
			if(h->length<0x0F) break;
			printf("\t\tSocket Designation: %s\n",
				dmi_string(h, data[0x04]));
			printf("\t\tConfiguration: %s, %s, Level %u\n",
				WORD(data+0x05)&0x0080?"Enabled":"Disabled",
				WORD(data+0x05)&0x0008?"Socketed":"Not Socketed",
				(WORD(data+0x05)&0x0007)+1);
			printf("\t\tOperational Mode: %s\n",
				dmi_cache_mode((WORD(data+0x05)>>8)&0x0003));
			printf("\t\tLocation: %s\n",
				dmi_cache_location((WORD(data+0x05)>>5)&0x0003));
			printf("\t\tInstalled Size:");
			dmi_cache_size(WORD(data+0x09));
			printf("\n");
			printf("\t\tMaximum Size:");
			dmi_cache_size(WORD(data+0x07));
			printf("\n");
			printf("\t\tSupported SRAM Types:");
			dmi_cache_types(WORD(data+0x0B), "\n\t\t\t");
			printf("\n");
			printf("\t\tInstalled SRAM Type:");
			dmi_cache_types(WORD(data+0x0D), " ");
			printf("\n");
			if(h->length<0x13) break;
			printf("\t\tSpeed:");
			dmi_memory_module_speed(data[0x0F]);
			printf("\n");
			printf("\t\tError Correction Type: %s\n",
				dmi_cache_ec_type(data[0x10]));
			printf("\t\tSystem Type: %s\n",
				dmi_cache_type(data[0x11]));
			printf("\t\tAssociativity: %s\n",
				dmi_cache_associativity(data[0x12]));
			break;
		
		case 8: /* 3.3.9 Port Connector Information */
			printf("\tPort Connector Information\n");
			if(h->length<0x09) break;
			printf("\t\tInternal Reference Designator: %s\n",
			   dmi_string(h, data[0x04]));
			printf("\t\tInternal Connector Type: %s\n",
			   dmi_port_connector_type(data[0x05]));
			printf("\t\tExternal Reference Designator: %s\n",
			   dmi_string(h, data[0x06]));
			printf("\t\tExternal Connector Type: %s\n",
			   dmi_port_connector_type(data[0x07]));
			printf("\t\tPort Type: %s\n",
			   dmi_port_type(data[0x08]));
			break;
		
		case 9: /* 3.3.10 System Slots */
			printf("\tSystem Slot Information\n");
			if(h->length<0x0C) break;
			printf("\t\tDesignation: %s\n", 
				dmi_string(h, data[0x04]));
			printf("\t\tType: %s%s\n",
				dmi_slot_bus_width(data[0x06]),
				dmi_slot_type(data[0x05]));
			printf("\t\tCurrent Usage: %s\n",
				dmi_slot_current_usage(data[0x07]));
			printf("\t\tLength: %s\n",
				dmi_slot_length(data[0x08]));
			dmi_slot_id(data[0x09], data[0x0A], data[0x05], "\t\t");
			printf("\t\tCharacteristics:");
			if(h->length<0x0D)
				dmi_slot_characteristics(data[0x0B], 0x00, "\t\t\t");
			else
				dmi_slot_characteristics(data[0x0B], data[0x0C], "\t\t\t");
			break;
		
		case 10: /* 3.3.11 On Board Devices Information */
			dmi_on_board_devices(h, "\t");
			break;
		
		case 11: /* 3.3.12 OEM Strings */
			printf("\tOEM Strings\n");
			if(h->length<0x05) break;
			dmi_oem_strings(h, "\t\t");
			break;	
		
		case 12: /* 3.3.13 System Configuration Options */
			printf("\tSystem Configuration Options\n");
			if(h->length<0x05) break;
			dmi_system_configuration_options(h, "\t\t");
			break;
		
		case 13: /* 3.3.14 BIOS Language Information */
			printf("\tBIOS Language Information\n");
			if(h->length<0x16) break;
			printf("\t\tInstallable Languages: %u\n", data[0x04]);
			dmi_bios_languages(h, "\t\t\t");
			printf("\t\tCurrently Installed Language: %s\n", dmi_string(h, data[0x15]));
			break;
		
		case 14: /* 3.3.15 Group Associations */
			printf("\tGroup Associations\n");
			if(h->length<0x05) break;
			printf("\t\tName: %s\n",
				dmi_string(h, data[0x04]));
			printf("\t\tItems: %u\n",
				(h->length-0x05)/3);
			dmi_group_associations_items((h->length-0x05)/3, data+0x05, "\t\t\t");
			break;
		
		case 15: /* 3.3.16 System Event Log */
			printf("\tSystem Event Log\n");
			if(h->length<0x14) break;
			printf("\t\tArea Length: %u bytes\n",
				WORD(data+0x04));
			printf("\t\tHeader Start Offset: 0x%04X\n",
				WORD(data+0x06));
			if(WORD(data+0x08)-WORD(data+0x06))
				printf("\t\tHeader Length: %u byte%s\n",
					WORD(data+0x08)-WORD(data+0x06),
					WORD(data+0x08)-WORD(data+0x06)>1?"s":"");
			printf("\t\tData Start Offset: 0x%04X\n",
				WORD(data+0x08));
			printf("\t\tAccess Method: %s\n",
				dmi_event_log_method(data[0x0A]));
			printf("\t\tAccess Address:");
			dmi_event_log_address(data[0x0A], data+0x10);
			printf("\n");
			printf("\t\tStatus:");
			dmi_event_log_status(data[0x0B]);
			printf("\n");
			printf("\t\tChange Token: 0x%08X\n",
				DWORD(data+0x0C));
			if(h->length<0x17) break;
			printf("\t\tHeader Format: %s\n",
				dmi_event_log_header_type(data[0x14]));
			printf("\t\tSupported Log Type Descriptors: %u\n",
				data[0x15]);
			if(h->length<0x17+data[0x15]*data[0x16]) break;
			dmi_event_log_descriptors(data[0x15], data[0x16], data+0x17, "\t\t");
			break;
		
		case 16: /* 3.3.17 Physical Memory Array */
			printf("\tPhysical Memory Array\n");
			if(h->length<0x0F) break;
			printf("\t\tLocation: %s\n",
				dmi_memory_array_location(data[0x04]));
			printf("\t\tUse: %s\n",
				dmi_memory_array_use(data[0x05]));
			printf("\t\tError Correction Type: %s\n",
				dmi_memory_array_ec_type(data[0x06]));
			printf("\t\tMaximum Capacity:");
			dmi_memory_array_capacity(DWORD(data+0x07));
			printf("\n");
			printf("\t\tError Information Handle:");
			dmi_memory_array_error_handle(WORD(data+0x0B));
			printf("\n");
			printf("\t\tNumber Of Devices: %u\n",
				WORD(data+0x0D));
			break;
		
		case 17: /* 3.3.18 Memory Device */
			printf("\tMemory Device\n");
			if(h->length<0x15) break;
			printf("\t\tArray Handle: 0x%04X\n",
				WORD(data+0x04));
			printf("\t\tError Information Handle:");
			dmi_memory_array_error_handle(WORD(data+0x06));
			printf("\n");
			printf("\t\tTotal Width:");
			dmi_memory_device_width(WORD(data+0x08));
			printf("\n");
			printf("\t\tData Width:");
			dmi_memory_device_width(WORD(data+0x0A));
			printf("\n");
			printf("\t\tSize:");
			dmi_memory_device_size(WORD(data+0x0C));
			printf("\n");
			printf("\t\tForm Factor: %s\n",
				dmi_memory_device_form_factor(data[0x0E]));
			printf("\t\tSet:");
			dmi_memory_device_set(data[0x0F]);
			printf("\n");
			printf("\t\tLocator: %s\n",
				dmi_string(h, data[0x10]));
			printf("\t\tBank Locator: %s\n",
				dmi_string(h, data[0x11]));
			printf("\t\tType: %s\n",
				dmi_memory_device_type(data[0x12]));
			printf("\t\tType Detail:");
			dmi_memory_device_type_detail(WORD(data+0x13));
			printf("\n");
			if(h->length<0x17) break;
			printf("\t\tSpeed:");
			dmi_memory_device_speed(WORD(data+0x15));
			printf("\n");
			if(h->length<0x1B) break;
			printf("\t\tManufacturer: %s\n",
				dmi_string(h, data[0x17]));
			printf("\t\tSerial Number: %s\n",
				dmi_string(h, data[0x18]));
			printf("\t\tAsset Tag: %s\n",
				dmi_string(h, data[0x19]));
			printf("\t\tPart Number: %s\n",
				dmi_string(h, data[0x1A]));
			break;
		
		case 18: /* 3.3.19 32-bit Memory Error Information */
			printf("\t32-bit Memory Error Information\n");
			if(h->length<0x17) break;
			printf("\t\tType: %s\n",
				dmi_memory_error_type(data[0x04]));
			printf("\t\tGranularity: %s\n",
				dmi_memory_error_granularity(data[0x05]));
			printf("\t\tOperation: %s\n",
				dmi_memory_error_operation(data[0x06]));
			printf("\t\tVendor Syndrome:");
			dmi_memory_error_syndrome(DWORD(data+0x07));
			printf("\n");
			printf("\t\tMemory Array Address:");
			dmi_32bit_memory_error_address(DWORD(data+0x0B));
			printf("\n");
			printf("\t\tDevice Address:");
			dmi_32bit_memory_error_address(DWORD(data+0x0F));
			printf("\n");
			printf("\t\tResolution:");
			dmi_32bit_memory_error_address(DWORD(data+0x13));
			printf("\n");
			break;
		
		case 19: /* 3.3.20 Memory Array Mapped Address */
			printf("\tMemory Array Mapped Address\n");
			if(h->length<0x0F) break;
			printf("\t\tStarting Address: 0x%08X%03X\n",
				DWORD(data+0x04)>>2, (DWORD(data+0x04)&0x3)<<10);
			printf("\t\tEnding Address: 0x%08X%03X\n",
				DWORD(data+0x08)>>2, ((DWORD(data+0x08)&0x3)<<10)+0x3FF);
			printf("\t\tRange Size:");
			dmi_mapped_address_size(DWORD(data+0x08)-DWORD(data+0x04)+1);
			printf("\n");
			printf("\t\tPhysical Array Handle: 0x%04X\n",
				WORD(data+0x0C));
			printf("\t\tPartition Width: %u\n",
				data[0x0F]);
			break;
		
		case 20: /* 3.3.21 Memory Device Mapped Address */
			printf("\tMemory Device Mapped Address\n");
			if(h->length<0x13) break;
			printf("\t\tStarting Address: 0x%08X%03X\n",
				DWORD(data+0x04)>>2, (DWORD(data+0x04)&0x3)<<10);
			printf("\t\tEnding Address: 0x%08X%03X\n",
				DWORD(data+0x08)>>2, ((DWORD(data+0x08)&0x3)<<10)+0x3FF);
			printf("\t\tRange Size:");
			dmi_mapped_address_size(DWORD(data+0x08)-DWORD(data+0x04)+1);
			printf("\n");
			printf("\t\tPhysical Device Handle: 0x%04X\n",
				WORD(data+0x0C));
			printf("\t\tMemory Array Mapped Address Handle: 0x%04X\n",
				WORD(data+0x0E));
			printf("\t\tPartition Row Position:");
			dmi_mapped_address_row_position(data[0x10]);
			printf("\n");
			dmi_mapped_address_interleave_position(data[0x11], "\t\t");
			dmi_mapped_address_interleaved_data_depth(data[0x12], "\t\t");
			break;
		
		case 21: /* 3.3.22 Built-in Pointing Device */
			printf("\tBuilt-in Pointing Device\n");
			if(h->length<0x07) break;
			printf("\t\tType: %s\n",
				dmi_pointing_device_type(data[0x04]));
			printf("\t\tInterface: %s\n",
				dmi_pointing_device_interface(data[0x05]));
			printf("\t\tButtons: %u\n",
				data[0x06]);
			break;
		
		case 22: /* 3.3.23 Portable Battery */
			printf("\tPortable Battery\n");
			if(h->length<0x10) break;
			printf("\t\tLocation: %s\n",
				dmi_string(h, data[0x04]));
			printf("\t\tManufacturer: %s\n",
				dmi_string(h, data[0x05]));
			if(data[0x06] || h->length<0x1A)
				printf("\t\tManufacture Date: %s\n",
					dmi_string(h, data[0x06]));
			if(data[0x07] || h->length<0x1A)
				printf("\t\tSerial Number: %s\n",
					dmi_string(h, data[0x07]));
			printf("\t\tName: %s\n",
				dmi_string(h, data[0x08]));
			if(data[0x09]!=0x02 || h->length<0x1A)
				printf("\t\tChemistry: %s\n",
					dmi_battery_chemistry(data[0x09]));
			printf("\t\tDesign Capacity:");
			if(h->length<0x1A)
				dmi_battery_capacity(WORD(data+0x0A), 1);
			else
				dmi_battery_capacity(WORD(data+0x0A), data[0x15]);
			printf("\n");
			printf("\t\tDesign Voltage:");
			dmi_battery_voltage(WORD(data+0x0C));
			printf("\n");
			printf("\t\tSBDS Version: %s\n",
				dmi_string(h, data[0x0E]));
			printf("\t\tMaximum Error:");
			dmi_battery_maximum_error(data[0x0E]);
			printf("\n");
			if(h->length<0x1A) break;
			if(data[0x07]==0)
				printf("\t\tSBDS Serial Number: %04X\n",
					WORD(data+0x10));
			if(data[0x06]==0)
				printf("\t\tSBDS Manufacture Date: %u-%02u-%02u\n",
					1980+(WORD(data+0x12)>>9), (WORD(data+0x12)>>5)&0x0F,
					WORD(data+0x12)&0x1F);
			if(data[0x09]==0x02)
				printf("\t\tSBDS Chemistry: %s\n",
					dmi_string(h, data[0x14]));
			printf("\t\tOEM-specific Information: 0x%08X\n",
				DWORD(data+0x16));
			break;
		
		case 23: /* 3.3.24 System Reset */
			printf("\tSystem Reset\n");
			if(h->length<0x0D) break;
			printf("\t\tStatus: %s\n",
				data[4]&(1<<0)?"Enabled":"Disabled");
			printf("\t\tWatchdog Timer: %s\n",
				data[4]&(1<<5)?"Present":"No");
			printf("\t\tBoot Option: %s\n",
				dmi_system_reset_boot_option((data[0x04]>>1)&0x3));
			printf("\t\tBoot Option On Limit: %s\n",
				dmi_system_reset_boot_option((data[0x04]>>3)&0x3));
			printf("\t\tReset Count:");
			dmi_system_reset_count(WORD(data+0x05));
			printf("\n");
			printf("\t\tReset Limit:");
			dmi_system_reset_count(WORD(data+0x07));
			printf("\n");
			printf("\t\tTimer Interval:");
			dmi_system_reset_timer(WORD(data+0x09));
			printf("\n");
			printf("\t\tTimeout:");
			dmi_system_reset_timer(WORD(data+0x0B));
			printf("\n");
			break;
		
		case 24: /* 3.3.25 Hardware Security */
			printf("\tHardware Security\n");
			if(h->length<0x05) break;
			printf("\t\tPower-On Password Status: %s\n",
				dmi_hardware_security_status(data[0x04]>>6));
			printf("\t\tKeyboard Password Status: %s\n",
				dmi_hardware_security_status((data[0x04]>>4)&0x3));
			printf("\t\tAdministrator Password Status: %s\n",
				dmi_hardware_security_status((data[0x04]>>2)&0x3));
			printf("\t\tFront Panel Reset Status: %s\n",
				dmi_hardware_security_status(data[0x04]&0x3));
			break;
		
		case 25: /* 3.3.26 System Power Controls */
			printf("\tSystem Power Controls\n");
			if(h->length<0x09) break;
			printf("\t\tNext Scheduled Power-on:");
			dmi_power_controls_power_on(data+0x04);
			printf("\n");
			break;
		
		case 26: /* 3.3.27 Voltage Probe */
			printf("\tVoltage Probe\n");
			if(h->length<0x14) break;
			printf("\t\tDescription: %s\n",
				dmi_string(h, data[0x04]));
			printf("\t\tLocation: %s\n",
				dmi_voltage_probe_location(data[0x05]&0x1f));
			printf("\t\tStatus: %s\n",
				dmi_probe_status(data[0x05]>>5));
			printf("\t\tMaximum Value:");
			dmi_voltage_probe_value(WORD(data+0x06));
			printf("\n");
			printf("\t\tMinimum Value:");
			dmi_voltage_probe_value(WORD(data+0x08));
			printf("\n");
			printf("\t\tResolution:");
			dmi_voltage_probe_resolution(WORD(data+0x0A));
			printf("\n");
			printf("\t\tTolerance:");
			dmi_voltage_probe_value(WORD(data+0x0C));
			printf("\n");
			printf("\t\tAccuracy:");
			dmi_probe_accuracy(WORD(data+0x0E));
			printf("\n");
			printf("\t\tOEM-specific Information: 0x%08X\n",
				DWORD(data+0x10));
			if(h->length<0x16) break;
			printf("\t\tNominal Value:");
			dmi_voltage_probe_value(WORD(data+0x14));
			printf("\n");
			break;
		
		case 27: /* 3.3.28 Cooling Device */
			printf("\tCooling Device\n");
			if(h->length<0x0C) break;
			if(WORD(data+0x04)!=0xFFFF)
				printf("\t\tTemperature Probe Handle: 0x%04X\n",
					WORD(data+0x04));
			printf("\t\tType: %s\n",
				dmi_cooling_device_type(data[0x06]&0x1f));
			printf("\t\tStatus: %s\n",
				dmi_probe_status(data[0x06]>>5));
			if(data[0x07]!=0x00)
				printf("\t\tCooling Unit Group: %u\n",
					data[0x07]);
			printf("\t\tOEM-specific Information: 0x%08X\n",
				DWORD(data+0x08));
			if(h->length<0x0E) break;
			printf("\t\tNominal Speed:");
			dmi_cooling_device_speed(WORD(data+0x0C));
			printf("\n");
			break;
		
		case 28: /* 3.3.29 Temperature Probe */
			printf("\tTemperature Probe\n");
			if(h->length<0x14) break;
			printf("\t\tDescription: %s\n",
				dmi_string(h, data[0x04]));
			printf("\t\tLocation: %s\n",
				dmi_temperature_probe_location(data[0x05]&0x1F));
			printf("\t\tStatus: %s\n",
				dmi_probe_status(data[0x05]>>5));
			printf("\t\tMaximum Value:");
			dmi_temperature_probe_value(WORD(data+0x06));
			printf("\n");
			printf("\t\tMinimum Value");
			dmi_temperature_probe_value(WORD(data+0x08));
			printf("\n");
			printf("\t\tResolution:");
			dmi_temperature_probe_resolution(WORD(data+0x0A));
			printf("\n");
			printf("\t\tTolerance:");
			dmi_temperature_probe_value(WORD(data+0x0C));
			printf("\n");
			printf("\t\tAccuracy:");
			dmi_probe_accuracy(WORD(data+0x0E));
			printf("\n");
			printf("\t\tOEM-specific Information: 0x%08X\n",
				DWORD(data+0x10));
			if(h->length<0x16) break;
			printf("\t\tNominal Value:");
			dmi_temperature_probe_value(WORD(data+0x14));
			printf("\n");
			break;
		
		case 29: /* 3.3.30 Electrical Current Probe */
			printf("\tElectrical Current Probe\n");
			if(h->length<0x14) break;
			printf("\t\tDescription: %s\n",
				dmi_string(h, data[0x04]));
			printf("\t\tLocation: %s\n",
			   dmi_voltage_probe_location(data[5]&0x1F));
			printf("\t\tStatus: %s\n",
				dmi_probe_status(data[0x05]>>5));
			printf("\t\tMaximum Value:");
			dmi_current_probe_value(WORD(data+0x06));
			printf("\n");
			printf("\t\tMinimum Value:");
			dmi_current_probe_value(WORD(data+0x08));
			printf("\n");
			printf("\t\tResolution:");
			dmi_current_probe_resolution(WORD(data+0x0A));
			printf("\n");
			printf("\t\tTolerance:");
			dmi_current_probe_value(WORD(data+0x0C));
			printf("\n");
			printf("\t\tAccuracy:");
			dmi_probe_accuracy(WORD(data+0x0E));
			printf("\n");
			printf("\t\tOEM-specific Information: 0x%08X\n",
				DWORD(data+0x10));
			if(h->length<0x16) break;
			printf("\t\tNominal Value:");
			dmi_current_probe_value(WORD(data+0x14));
			printf("\n");
			break;
		
		case 30: /* 3.3.31 Out-of-band Remote Access */
			printf("\tOut-of-band Remote Access\n");
			if(h->length<0x06) break;
			printf("\t\tManufacturer Name: %s\n",
				dmi_string(h, data[0x04]));
			printf("\t\tInbound Connection: %s\n",
				data[0x05]&(1<<0)?"Enabled":"Disabled");
			printf("\t\tOutbound Connection: %s\n",
				data[0x05]&(1<<1)?"Enabled":"Disabled");
			break;
		
		case 31: /* 3.3.32 Boot Integrity Services Entry Point */
			printf("\tBoot Integrity Services Entry Point\n");
			break;
		
		case 32: /* 3.3.33 System Boot Information */
			printf("\tSystem Boot Information\n");
			if(h->length<0x0B) break;
			printf("\t\tStatus: %s\n",
				dmi_system_boot_status(data[0x0A]));
			break;
		
		case 33: /* 3.3.34 64-bit Memory Error Information */
			if(h->length<0x1F) break;
			printf("\t64-bit Memory Error Information\n");
			printf("\t\tType: %s\n",
				dmi_memory_error_type(data[0x04]));
			printf("\t\tGranularity: %s\n",
				dmi_memory_error_granularity(data[0x05]));
			printf("\t\tOperation: %s\n",
				dmi_memory_error_operation(data[0x06]));
			printf("\t\tVendor Syndrome:");
			dmi_memory_error_syndrome(DWORD(data+0x07));
			printf("\n");
			printf("\t\tMemory Array Address:");
			dmi_64bit_memory_error_address(QWORD(data+0x0B));
			printf("\n");
			printf("\t\tDevice Address:");
			dmi_64bit_memory_error_address(QWORD(data+0x13));
			printf("\n");
			printf("\t\tResolution:");
			dmi_32bit_memory_error_address(DWORD(data+0x1B));
			printf("\n");
			break;
		
		case 34: /* 3.3.35 Management Device */
			printf("\tManagement Device\n");
			if(h->length<0x0B) break;
			printf("\t\tDescription: %s\n",
				dmi_string(h, data[0x04]));
			printf("\t\tType: %s\n",
			    dmi_management_device_type(data[0x05]));
			printf("\t\tAddress: 0x%08X\n",
				DWORD(data+0x06));
			printf("\t\tAddress Type: %s\n",
			    dmi_management_device_address_type(data[0x0A]));
			break;
		
		case 35: /* 3.3.36 Management Device Component */
			printf("\tManagement Device Component\n");
			if(h->length<0x0B) break;
			printf("\t\tDescription: %s\n",
				dmi_string(h, data[0x04]));
			printf("\t\tManagement Device Handle: 0x%04X\n",
			    WORD(data+0x05));
			printf("\t\tComponent Handle: 0x%04X\n",
			    WORD(data+0x07));
			if(WORD(data+0x09)!=0xFFFF)
				printf("\t\tThreshold Handle: 0x%04X\n",
			    	WORD(data+0x09));
			break;
		
		case 36: /* 3.3.37 Management Device Threshold Data */
			printf("\tManagement Device Threshold Data\n");
			if(h->length<0x10) break;
			if(WORD(data+0x04)!=0x8000)
				printf("\t\tLower Non-critical Threshold: %d\n",
					(i16)WORD(data+0x04));
			if(WORD(data+0x06)!=0x8000)
				printf("\t\tUpper Non-critical Threshold: %d\n",
					(i16)WORD(data+0x06));
			if(WORD(data+0x08)!=0x8000)
				printf("\t\tLower Critical Threshold: %d\n",
					(i16)WORD(data+0x08));
			if(WORD(data+0x0A)!=0x8000)
				printf("\t\tUpper Critical Threshold: %d\n",
					(i16)WORD(data+0x0A));
			if(WORD(data+0x0C)!=0x8000)
				printf("\t\tLower Non-recoverable Threshold: %d\n",
					(i16)WORD(data+0x0C));
			if(WORD(data+0x0E)!=0x8000)
				printf("\t\tUpper Non-recoverable Threshold: %d\n",
					(i16)WORD(data+0x0E));
			break;
		
		case 37: /* 3.3.38 Memory Channel */
			printf("\tMemory Channel\n");
			if(h->length<0x07) break;
			printf("\t\tType: %s\n",
				dmi_memory_channel_type(data[0x04]));
			printf("\t\tMaximal Load: %u\n",
				data[0x05]);
			printf("\t\tDevices: %u\n",
				data[0x06]);
			if(h->length<0x07+3*data[0x06]) break;
			dmi_memory_channel_devices(data[0x06], data+0x07, "\t\t\t");
			break;
		
		case 38: /* 3.3.39 IPMI Device Information */
			/*
			 * We use the word "Version" instead of "Revision", conforming to
			 * the IPMI 1.5 specification.
			 */
			printf("\tIPMI Device Information\n");
			if(h->length<0x10) break;
			printf("\t\tInterface Type: %s\n",
				dmi_ipmi_interface_type(data[0x04]));
			printf("\t\tSpecification Version: %u.%u\n",
				data[0x05]>>4, data[0x05]&0x0F);
			printf("\t\tI2C Slave Address: 0x%02x\n",
				data[0x06]>>1);
			if(data[0x07]!=0xFF)
				printf("\t\tNV Storage Device Address: %u\n",
					data[0x07]);
			else
				printf("\t\tNV Storage Device: Not Present\n");
			if(h->length<0x12)
			{
				printf("\t\tBase Address: 0x%08X%08X (%s)\n",
					QWORD(data+0x08).h, QWORD(data+0x08).l,
					QWORD(data+0x08).l&1?"I/O":"Memory-mapped");
				break;
			}
			printf("\t\tBase Address: 0x%08X%08X (%s)\n",
				QWORD(data+0x08).h,
				(QWORD(data+0x08).l&~1)|((data[0x10]>>5)&1),
				QWORD(data+0x08).l&1?"I/O":"Memory-mapped");
			printf("\t\tRegister Spacing: %s\n",
				dmi_ipmi_register_spacing(data[0x10]>>6));
			if(data[0x10]&(1<<3))
			{
				printf("\t\tInterrupt Polarity: %s\n",
					data[0x10]&(1<<1)?"Active High":"Active Low");
				printf("\t\tInterrupt Trigger Mode: %s\n",
					data[0x10]&(1<<0)?"Level":"Edge");
			}
			if(data[0x11]!=0x00)
			{
				printf("\t\tInterrupt Number: %x\n",
					data[0x11]);
			}
			break;
		
		case 39: /* 3.3.40 System Power Supply */
			printf("\tSystem Power Supply\n");
			if(h->length<0x10) break;
			if(data[0x04]!=0x00)
				printf("\t\tPower Unit Group: %u\n",
					data[0x04]);
			printf("\t\tLocation: %s\n",
				dmi_string(h, data[0x05]));
			printf("\t\tName: %s\n",
				dmi_string(h, data[0x06]));
			printf("\t\tManufacturer: %s\n",
				dmi_string(h, data[0x07]));
			printf("\t\tSerial Number: %s\n",
				dmi_string(h, data[0x08]));
			printf("\t\tAsset Tag: %s\n",
				dmi_string(h, data[0x09]));
			printf("\t\tModel Part Number: %s\n",
				dmi_string(h, data[0x0A]));
			printf("\t\tRevision: %s\n",
				dmi_string(h, data[0x0B]));
			printf("\t\tMax Power Capacity:");
			dmi_power_supply_power(WORD(data+0x0C));
			printf("\n");
			printf("\t\tStatus:");
			if(WORD(data+0x0E)&(1<<1))
				printf(" Present, %s",
					dmi_power_supply_status((WORD(data+0x0E)>>7)&0x07));
			else
				printf(" Not Present");
			printf("\n");
			printf("\t\tType: %s\n",
				dmi_power_supply_type((WORD(data+0x0E)>>10)&0x0F));
			printf("\t\tInput Voltage Range Switching: %s\n",
				dmi_power_supply_range_switching((WORD(data+0x0E)>>3)&0x0F));
			printf("\t\tPlugged: %s\n",
				WORD(data+0x0E)&(1<<2)?"No":"Yes");
			printf("\t\tHot Replaceable: %s\n",
				WORD(data+0x0E)&(1<<0)?"Yes":"No");
			if(h->length<0x16) break;
			if(WORD(data+0x10)!=0xFFFF)
				printf("\t\tInput Voltage Probe Handle: 0x%04X\n",
					WORD(data+0x10));
			if(WORD(data+0x12)!=0xFFFF)
				printf("\t\tCooling Device Handle: 0x%04X\n",
					WORD(data+0x12));
			if(WORD(data+0x14)!=0xFFFF)
				printf("\t\tInput Current Probe Handle: 0x%04X\n",
					WORD(data+0x14));
			break;
		
		case 126: /* 3.3.41 Inactive */
			printf("\tInactive\n");
			break;
		
		case 127: /* 3.3.42 End Of Table */
			printf("\tEnd Of Table\n");
			break;
		
		default:
			printf("\t%s Type\n",
				h->type>=128?"OEM-specific":"Unknown");
			dmi_dump(h, "\t\t");
	}
}
		
static void dmi_table(int fd, u32 base, u16 len, u16 num, u16 ver, const char *pname, const char *devmem)
{
	u8 *buf;
	u8 *data;
	int i=0;
#ifdef USE_MMAP
	u32 mmoffset;
	void *mmp;
#endif /* USE_MMAP */
	
	printf("%u structures occupying %u bytes.\n",
		num, len);
	printf("Table at 0x%08X.\n",
		base);
	
	if((buf=malloc(len))==NULL)
	{
		perror(pname);
		return;
	}
#ifdef USE_MMAP
	mmoffset=base%getpagesize();
	/*
	 * We were previously using PROT_WRITE and MAP_PRIVATE, but it caused
	 * trouble once. So we are now mapping in read-only mode and copying
	 * the interesting block into a regular memory buffer (similar to what
	 * we do when not using mmap.)
	 */
	mmp=mmap(0, mmoffset+len, PROT_READ, MAP_SHARED, fd, base-mmoffset);
	if(mmp==MAP_FAILED)
	{
		free(buf);
    	perror(devmem);
    	return;
	}
	memcpy(buf, (u8 *)mmp+mmoffset, len);
	if(munmap(mmp, mmoffset+len)==-1)
		perror(devmem);
#else /* USE_MMAP */
	if(lseek(fd, (off_t)base, SEEK_SET)==-1)
	{
		perror(devmem);
		return;
	}
	if(myread(fd, buf, len, devmem)==-1)
	{
		free(buf);
		printf("Table is unreachable, sorry. Try compiling dmidecode with -DUSE_MMAP.\n"
			"This problem is known on the IBM T23, T30 and X30 laptops, the Fujitsu-Siemens\n"
			"S-4582 laptop as well as IA-64 systems. If your system differ, please report\n");
		exit(1);
	}
#endif /* USE_MMAP */
	
	data=buf;
	while(i<num && data+sizeof(struct dmi_header)<=buf+len)
	{
		u8 *next;
		struct dmi_header *h=(struct dmi_header *)data;
		
		printf("Handle 0x%04X\n\tDMI type %d, %d bytes.\n",
			HANDLE(h), h->type, h->length);
		
		/* look for the next handle */
		next=data+h->length;
		while(next-buf+1<len && (next[0]!=0 || next[1]!=0))
			next++;
		next+=2;
		if(next-buf<=len)
			dmi_decode(data, ver);
		else
			printf("\t<TRUNCATED>\n");
		
		data=next;
		i++;
	}
	
	if(i!=num)
		printf("Wrong DMI structures count: %d announced, only %d decoded.\n",
			num, i);
	if(data-buf!=len)
		printf("Wrong DMI structures length: %d bytes announced, structures occupy %d bytes.\n",
			len, (unsigned int)(data-buf));
	
	free(buf);
}


static int smbios_decode(u8 *buf, int fd, const char *pname, const char *devmem)
{
	if(checksum(buf, buf[0x05])
	 && memcmp(buf+0x10, "_DMI_", 5)==0
	 && checksum(buf+0x10, 0x0F))
	{
		printf("SMBIOS %u.%u present.\n",
			buf[0x06], buf[0x07]);
		dmi_table(fd, DWORD(buf+0x18), WORD(buf+0x16), WORD(buf+0x1C),
			(buf[0x06]<<8)+buf[0x07], pname, devmem);
		return 1;
	}
	
	return 0;
}

int main(int argc, const char *argv[])
{
	int fd, found=0;
	off_t fp=0xF0000;
	const char *devmem="/dev/mem";
#ifdef __IA64__
	FILE *efi_systab;
	char linebuf[64];
#ifdef USE_MMAP
	u32 mmoffset;
	void *mmp;
#else /* USE_MMAP */
	u8 buf[0x20];
#endif /* USE_MMAP */
#else /* __IA64__ */
	u8 buf[0x20];
#endif /* __IA64__ */
	
	if(sizeof(u8)!=1 || sizeof(u16)!=2 || sizeof(u32)!=4 || '\0'!=0)
	{
		fprintf(stderr,"%s: compiler incompatibility\n", argv[0]);
		exit(255);
	}
	
	if(argc>=2)
		devmem=argv[1];
	if((fd=open(devmem, O_RDONLY))==-1)
	{
		perror(devmem);
		exit(1);
	}
	
	printf("# dmidecode %s\n", VERSION);
	
#ifdef __IA64__
	if((efi_systab=fopen("/proc/efi/systab", "r"))==NULL)
	{
		perror("/proc/efi/systab");
		exit(1);
	}
	while((fgets(linebuf, sizeof(linebuf)-1, efi_systab))!=NULL)
	{
		char* addr=memchr(linebuf, '=', strlen(linebuf));
		*(addr++)='\0';
		if(strcmp(linebuf, "SMBIOS")==0)
		{
			fp=strtol(addr, NULL, 0);
			printf("# SMBIOS entry point at 0x%08lx\n", fp);
		}
	}
	if(fclose(efi_systab)!=0)
		perror("/proc/efi/systab");

#ifdef USE_MMAP
	mmoffset=fp%getpagesize();
	mmp=mmap(0, mmoffset+0x20, PROT_READ, MAP_PRIVATE, fd, fp-mmoffset);
    if(mmp==MAP_FAILED)
    {
       perror(devmem);
       exit(1);
    }

	smbios_decode(((u8 *)mmp)+mmoffset, fd, argv[0], devmem);

	if(munmap(mmp, mmoffset+0x20)==-1)
		perror(devmem);
#else /* USE_MMAP */
	if(lseek(fd, fp, SEEK_SET)==-1)
	{
		perror(devmem);
		exit(1);
	}
	if(myread(fd, buf, 0x20, devmem)==-1)
		exit(1);

	smbios_decode(buf, fd, argv[0], devmem);
#endif /* USE_MMAP */
	found++;
#else /* __IA64__ */
	if(lseek(fd, fp, SEEK_SET)==-1)
	{
		perror(devmem);
		exit(1);
	}
	while(fp<=0xFFFF0)
	{
		if(myread(fd, buf, 0x10, devmem)==-1)
			exit(1);
		fp+=16;
		
		if(memcmp(buf, "_SM_", 4)==0 && fp<=0xFFFF0)
		{
			if(myread(fd, buf+0x10, 0x10, devmem)==-1)
				exit(1);
			fp+=16;
			
			if(smbios_decode(buf, fd, argv[0], devmem))
			{
#ifndef USE_MMAP
				/* dmi_table moved us far away */
				lseek(fd, fp, SEEK_SET);
#endif /* USE_MMAP */
				found++;
			}
		}
		else if(memcmp(buf, "_DMI_", 5)==0
		 && checksum(buf, 0x0F))
		{
			printf("Legacy DMI %u.%u present.\n",
				buf[0x0E]>>4, buf[0x0E]&0x0F);
			dmi_table(fd, DWORD(buf+0x08), WORD(buf+0x06), WORD(buf+0x0C),
				((buf[0x0E]&0xF0)<<4)+(buf[0x0E]&0x0F), argv[0], devmem);
			
#ifndef USE_MMAP
			/* dmi_table moved us far away */
			lseek(fd, fp, SEEK_SET);
#endif /* USE_MMAP */
			found++;
		}
	}
#endif /* __IA64__ */
	
	if(close(fd)==-1)
	{
		perror(devmem);
		exit(1);
	}
	
	if(!found)
		printf("# No SMBIOS nor DMI entry point found, sorry.\n");

	return 0;
}
