#ifndef _DUMP_FILTER_H_
#define _DUMP_FILTER_H_

#include <ntdddisk.h>
#include <ntdddump.h>

NTSTATUS dump_filter_DriverEntry(IN PFILTER_EXTENSION           FilterExtension,     // FILTER_EXTENSION structure, passed by OS in 1st parameter of DriverEntry
	                             IN PFILTER_INITIALIZATION_DATA InitializationData); // FILTER_INITIALIZATION_DATA structure, passed by OS in 2nd parameter of DriverEntry

#endif