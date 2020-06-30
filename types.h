#ifndef TYPES_H
#define TYPES_H

#include "config.h"

typedef unsigned char u8;
typedef unsigned short u16;
typedef signed short i16;
typedef unsigned int u32;

/*
 * You may use the following defines to adjust the type definitions
 * depending on the architecture:
 * - Define BIGENDIAN on big-endian systems.
 * - Define ALIGNMENT_WORKAROUND if your system doesn't support
 *   non-aligned memory access. In this case, we use a slower, but safer,
 *   memory access method. This should be done automatically in config.h
 *   for architectures which need it.
 */

#ifdef BIGENDIAN
typedef struct {
	u32 h;
	u32 l;
} u64;
#else
typedef struct {
	u32 l;
	u32 h;
} u64;
#endif

#if defined(ALIGNMENT_WORKAROUND) || defined(BIGENDIAN)
static inline u64 U64(u32 low, u32 high)
{
	u64 self;

	self.l = low;
	self.h = high;

	return self;
}
#endif

enum dmi_types{
	BIOS,
	SYSTEM,
	BASEBOARD,
	CHASSIS,
	PROCESSOR,
	MEMORY_CONTROLLER,
	MEMORY_MODULE,
	CACHE,
	PORT_CONNECTOR,
	SYSTEM_SLOTS,
	ON_BOARD_DEVICES,
	OEM_STRINGS,
	SYSTEM_CONFIGURATION_OPTIONS,
	BIOS_LANGUAGE,
	GROUP_ASSOCIATIONS,
	SYSTEM_EVENT_LOG,
	PHYSICAL_MEMORY_ARRAY,
	MEMORY_DEVICE,
	MEMORY_ERROR_32_BIT,
	MEMORY_ARRAY_MAPPED_ADDRESS,
	MEMORY_DEVICE_MAPPED_ADDRESS,
	BUILT_IN_POINTING_DEVICE,
	PORTABLE_BATTERY,
	SYSTEM_RESET,
	HARDWARE_SECURITY,
	SYSTEM_POWER_CONTROLS,
	VOLTAGE_PROBE,
	COOLING_DEVICE,
	TEMPERATURE_PROBE,
	ELECTRICAL_CURRENT_PROBE,
	OUT_OF_BAND_REMOTE_ACCESS,
	BOOT_INTEGRITY_SERVICES,
	SYSTEM_BOOT,
	MEMORY_ERROR_64_BIT,
	MANAGEMENT_DEVICE,
	MANAGEMENT_DEVICE_COMPONENT,
	MANAGEMENT_DEVICE_THRESHOLD_DATA,
	MEMORY_CHANNEL,
	IPMI_DEVICE,
	POWER_SUPPLY,
	ADDITIONAL_INFORMATION,
	ONBOARD_DEVICES_EXTENDED_INFORMATION,
	MANAGEMENT_CONTROLLER_HOST_INTERFACE
};

/*
 * Per SMBIOS v2.8.0 and later, all structures assume a little-endian
 * ordering convention.
 */
#if defined(ALIGNMENT_WORKAROUND) || defined(BIGENDIAN)
#define WORD(x) (u16)((x)[0] + ((x)[1] << 8))
#define DWORD(x) (u32)((x)[0] + ((x)[1] << 8) + ((x)[2] << 16) + ((x)[3] << 24))
#define QWORD(x) (U64(DWORD(x), DWORD(x + 4)))
#else /* ALIGNMENT_WORKAROUND || BIGENDIAN */
#define WORD(x) (u16)(*(const u16 *)(x))
#define DWORD(x) (u32)(*(const u32 *)(x))
#define QWORD(x) (*(const u64 *)(x))
#endif /* ALIGNMENT_WORKAROUND || BIGENDIAN */

#endif
