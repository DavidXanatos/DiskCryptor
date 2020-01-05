#ifndef _DUMP_HELPERS_H_
#define _DUMP_HELPERS_H_

typedef NTSTATUS (*PDC_DUMP_START)(__in BOOLEAN is_hibernation);
typedef void (*PDC_DUMP_FINISH)();

typedef NTSTATUS (*PDC_DUMP_ENCRYPT)(
	__inout PLARGE_INTEGER DiskByteOffset,
	__in    PMDL           Mdl,
	__out   PUCHAR         EncryptedData
	);

typedef BOOLEAN (*PDC_DUMP_IS_HIBERNATION_ALLOWED)();

typedef struct {
	PDC_DUMP_START                  dump_start;
	PDC_DUMP_FINISH                 dump_finish;
	PDC_DUMP_ENCRYPT                dump_encrypt;
	PDC_DUMP_IS_HIBERNATION_ALLOWED dump_is_hibernation_allowed;

} DC_DUMP_HELPERS;

extern DC_DUMP_HELPERS dc_dump_helpers;

#endif