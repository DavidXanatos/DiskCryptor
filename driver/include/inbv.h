#ifndef _INBV_H_
#define _INBV_H_

VOID
NTAPI
InbvAcquireDisplayOwnership(
    VOID
);

BOOLEAN
NTAPI
InbvEnableDisplayString(
    IN BOOLEAN Enable
);

BOOLEAN
NTAPI
InbvDisplayString(
    IN PCHAR String
);

    
#endif

