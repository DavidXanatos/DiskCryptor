#ifndef _DC_HEADER_H_
#define _DC_HEADER_H_

#include "..\volume.h"
#include "..\..\crypto\xts_small.h"

int dc_decrypt_header(dc_header *header, dc_pass *password);

#endif