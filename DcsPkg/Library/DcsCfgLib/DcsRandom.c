/** @file
Random number generators for DCS

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0

!NOTE: Very simple! Need to select several sources of random like user input or other.
**/

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/CommonLib.h>
#include <Library/RngLib.h>
#include <Library/DcsCfgLib.h>
#include <Library/BaseCryptLib.h>

#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

#ifdef CFG_RND_USE_TPM
#include <Library/DcsTpmLib.h>
#endif

#define SHA512_BLOCK_SIZE  128

DCS_RND* gRnd = NULL;

//////////////////////////////////////////////////////////////////////////
// Random data from file
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
RndFilePrepare(
	IN DCS_RND* rnd
	) 
{
	EFI_STATUS res = EFI_NOT_READY;
	if (rnd != NULL && rnd->Type == RndTypeFile && rnd->State.File.Data != NULL) {
		rnd->State.File.Pos = 0;
		res = EFI_SUCCESS;
	}
	return res;
}

EFI_STATUS
RndFileGetBytes(
	IN  DCS_RND *rnd,
	OUT UINT8   *buf,
	IN  UINTN    len) 
{
	UINTN    i;
	if (rnd != NULL && rnd->Type == RndTypeFile && rnd->State.File.Data != NULL) {
		for (i = 0; i < len; i++, rnd->State.File.Pos++) {
			if (rnd->State.File.Pos >= rnd->State.File.Size) {
				rnd->State.File.Pos = 0;
			}
			buf[i] = rnd->State.File.Data[rnd->State.File.Pos];
		}
	}
	return EFI_SUCCESS;
}

EFI_STATUS
RndFileInit(
	IN DCS_RND* rnd,
	IN VOID* Context,
	IN UINTN ContextSize
	)
{
	EFI_STATUS res = EFI_NOT_FOUND;
	if (Context != NULL) {
		ZeroMem(rnd, sizeof(DCS_RND));
		rnd->Type = RndTypeFile;
		rnd->GetBytes = RndFileGetBytes;
		rnd->Prepare = RndFilePrepare;
		rnd->State.File.Data = Context;
		rnd->State.File.Size = ContextSize;
		res = EFI_SUCCESS;
	}
	return res;
}

//////////////////////////////////////////////////////////////////////////
// Random data from CPU RDRAND
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
RndRDRandPrepare(
	IN DCS_RND* rnd
	)
{
	UINT64 rndTmp;
	if (rnd != NULL && rnd->Type == RndTypeRDRand) {
		if (GetRandomNumber64((UINT64*)&rndTmp)) {
			return EFI_SUCCESS;
		}
	}
	return EFI_NOT_READY;
}

EFI_STATUS
RndRDRandGetBytes(
	IN  DCS_RND *rnd,
	OUT UINT8   *buf,
	IN  UINTN    len)
{
	UINT8 tmpRnd[8];
	UINTN i = 0;
	UINTN j = 0;
	if (rnd != NULL && rnd->Type == RndTypeRDRand) {
		for (i = 0; i < len; ++i, ++j) {
			j &= 7;
			if (j == 0) {
				if (!GetRandomNumber64((UINT64*)tmpRnd)) return EFI_NOT_READY;
			}
			buf[i] = tmpRnd[j];
		}
	}	else {
		return EFI_NOT_READY;
	}
	return EFI_SUCCESS;
}

EFI_STATUS
RndRDRandInit(
	IN DCS_RND* rnd,
	IN VOID* Context,
	IN UINTN ContextSize
	)
{
	ZeroMem(rnd, sizeof(DCS_RND));
	rnd->Type = RndTypeRDRand;
	rnd->GetBytes = RndRDRandGetBytes;
	rnd->Prepare = RndRDRandPrepare;
	return rnd->Prepare(rnd);
}

//////////////////////////////////////////////////////////////////////////
// DRBG HMAC (SHA512) (NIST SP 800-90A) (simplified)
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
HmacSha512(
	IN  UINT8         *k,				/* secret key */
	OUT UINT8         *out,				/* output buffer */
   ...
	)
{
	UINT8 ctxBuf[256];
	VOID *ctx = (VOID *)ctxBuf;
	UINT8 inner[SHA512_DIGEST_SIZE];
	UINT8 buf[SHA512_BLOCK_SIZE];
	int i;
	int lk = SHA512_DIGEST_SIZE;	/* length of the key in bytes */
	VA_LIST args;
	UINT8* data;
	UINTN  len;

	ASSERT(Sha512GetContextSize() <= sizeof(ctxBuf));

	/**** Inner Digest ****/
	Sha512Init(ctx);

	/* Pad the key for inner digest */
	for (i = 0; i < lk; ++i)
		buf[i] = (UINT8)(k[i] ^ 0x36);
	for (i = lk; i < SHA512_BLOCK_SIZE; ++i)
		buf[i] = 0x36;

	Sha512Update(ctx, buf, SHA512_BLOCK_SIZE);

	VA_START(args, out);
	while ((data = VA_ARG(args, UINT8 *)) != NULL) {
		len = VA_ARG(args, UINTN);
		Sha512Update(ctx, data, len);
	}
	VA_END(args);

	Sha512Final(ctx, inner);

	/**** Outer Digest ****/

	Sha512Init(ctx);

	for (i = 0; i < lk; ++i)
		buf[i] = (UINT8)(k[i] ^ 0x5C);
	for (i = lk; i < SHA512_BLOCK_SIZE; ++i)
		buf[i] = 0x5C;

	Sha512Update(ctx, buf, SHA512_BLOCK_SIZE);
	Sha512Update(ctx, inner, SHA512_DIGEST_SIZE);

	Sha512Final(ctx, out);

	/* Prevent possible leaks. */
	ZeroMem(ctxBuf, sizeof(ctxBuf));
	ZeroMem(inner, sizeof(inner));
	ZeroMem(buf, sizeof(buf));
	return EFI_SUCCESS;
}

EFI_STATUS
RndDtrmHmacSha512Update(
	RND_DTRM_HMAC_SHA512_STATE     *state,
	UINT8                          *seed, 
	UINTN                          seedLen,
	BOOLEAN                        reseed
	)
{
	EFI_STATUS res = EFI_NOT_READY;
	int i = 0;

	if (!reseed)
	{
		/* 10.1.2.3 */
		SetMem(state->V, SHA512_DIGEST_SIZE, 1);
		ZeroMem(state->C, SHA512_DIGEST_SIZE);
	}

	/* we execute two rounds of V/K massaging */
	for (i = 2; 0 < i; i--)
	{
		/* first round uses 0x0, second 0x1 */
		unsigned char prefix = 0;
		if (1 == i)
			prefix = 1;
		/* 10.1.2.2 step 1 and 4 -- concatenation and HMAC for key */

		res = HmacSha512(state->C, state->C, 
			state->V, SHA512_DIGEST_SIZE,
			&prefix, 1,
			seed,    seedLen,
			NULL
			);
		if (EFI_ERROR(res))
			return res;

		/* 10.1.2.2 step 2 and 5 -- HMAC for V */
		res = HmacSha512(state->C, state->V, 
			state->V, SHA512_DIGEST_SIZE,
			NULL);

		if (EFI_ERROR(res))
			return res;

		/* 10.1.2.2 step 3 */
		if (!seed || 0 == seedLen)
			return res;
	}
	return EFI_SUCCESS;
}

/* generate function of HMAC DRBG as defined in 10.1.2.5 */
EFI_STATUS
RndDtrmHmacSha512Generate(
	RND_DTRM_HMAC_SHA512_STATE         *state,
	OUT UINT8                          *buf,
	IN  UINTN                          buflen,
	IN  UINT8                          *seed,
	IN  UINTN                          seedLen
	)
{
	EFI_STATUS     res = EFI_SUCCESS;
	UINTN          len = 0;

	/* 10.1.2.5 step 2 */
	if (seed && 0 < seedLen)
	{
		res = RndDtrmHmacSha512Update(state, seed, seedLen, 1);
		if (EFI_ERROR(res))
			return res;
	}

	while (len < buflen)
	{
		UINTN outlen = 0;
		/* 10.1.2.5 step 4.1 */
		res = HmacSha512(state->C, state->V, 
			state->V, SHA512_DIGEST_SIZE,
			NULL
			);
		if (EFI_ERROR(res))
			return res;
		outlen = (SHA512_DIGEST_SIZE < (buflen - len)) ?
			SHA512_DIGEST_SIZE : (buflen - len);

		/* 10.1.2.5 step 4.2 */
		CopyMem(buf + len, state->V, outlen);
		len += outlen;
	}

	/* 10.1.2.5 step 6 */
	res = RndDtrmHmacSha512Update(state, seed, seedLen, 1);
	return res;
}

EFI_STATUS
RndDtrmHmacSha512Prepare(
	IN DCS_RND* rnd
	)
{
	if (rnd != NULL && rnd->Type == RndTypeDtrmHmacSha512) {
		return EFI_SUCCESS;
	}
	return EFI_NOT_READY;
}

EFI_STATUS
RndDtrmHmacSha512GetBytes(
	IN DCS_RND* rnd,
	UINT8 *buf,
	UINTN len
	)
{
	EFI_TIME seed;
	EFI_STATUS res = EFI_NOT_READY;
	RND_DTRM_HMAC_SHA512_STATE *state = &rnd->State.HMacSha512;
	if (state->ReseedCtr < (1LL << 48)) {
		gST->RuntimeServices->GetTime(&seed, NULL);
		res = RndDtrmHmacSha512Generate(state, buf, len, (UINT8*)&seed, sizeof(seed));
		state->ReseedCtr++;
	}
	return res;
}

EFI_STATUS
RndDtrmHmacSha512Init(
	IN DCS_RND* rnd,
	IN VOID* Context,
	IN UINTN ContextSize)
{
	EFI_STATUS res = EFI_SUCCESS;
	ZeroMem(rnd, sizeof(DCS_RND));
	rnd->Type = RndTypeDtrmHmacSha512;
	rnd->GetBytes = RndDtrmHmacSha512GetBytes;
	rnd->Prepare = RndDtrmHmacSha512Prepare;

	if (Context != NULL) {
		res = RndDtrmHmacSha512Update(&rnd->State.HMacSha512, (UINT8*)Context, ContextSize, 0);
		if (EFI_ERROR(res)) {
			rnd->Type = RndTypeNone;
		}
	}
	return rnd->Prepare(rnd);
}

//////////////////////////////////////////////////////////////////////////
// OpenSSL random
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
RndOpenSSLPrepare(
	IN DCS_RND* rnd
	)
{
	UINT64 rndTmp;
	if (rnd != NULL && rnd->Type == RndTypeOpenSSL) {
		if (RandomBytes((UINT8*)&rndTmp, 8)) {
			return EFI_SUCCESS;
		}
	}
	return EFI_NOT_READY;
}

EFI_STATUS
RndOpenSSLGetBytes(
	IN  DCS_RND *rnd,
	OUT UINT8   *buf,
	IN  UINTN    len)
{
	if (rnd != NULL && rnd->Type == RndTypeOpenSSL) {
		if (RandomBytes(buf, len)) {
			return EFI_SUCCESS;
		}
	}
	return EFI_NOT_READY;
}

EFI_STATUS
RndOpenSSLInit(
	IN DCS_RND* rnd,
	IN VOID* Context,
	IN UINTN ContextSize
	)
{
	int res;
	ZeroMem(rnd, sizeof(DCS_RND));
	rnd->Type = RndTypeOpenSSL;
	rnd->GetBytes = RndOpenSSLGetBytes;
	rnd->Prepare = RndOpenSSLPrepare;
	res = RandomSeed(Context, ContextSize);
	if (!res) {
		return EFI_NOT_READY;
	}
	return rnd->Prepare(rnd);
}

//////////////////////////////////////////////////////////////////////////
// TPM random
//////////////////////////////////////////////////////////////////////////
#ifdef CFG_RND_USE_TPM

EFI_STATUS
RndTpmPrepare(
	IN DCS_RND* rnd
	)
{
	UINT64 rndTmp;
	UINT32 sz = sizeof(rndTmp);
	if (rnd != NULL && rnd->Type == RndTypeTpm && !EFI_ERROR(GetTpm())) {
		return gTpm->GetRandom(gTpm, sz, (UINT8*)&rndTmp);
	}
	return EFI_NOT_READY;
}

EFI_STATUS
RndTpmGetBytes(
	IN  DCS_RND *rnd,
	OUT UINT8   *buf,
	IN  UINTN    len)
{
	if (rnd != NULL && rnd->Type == RndTypeTpm && !EFI_ERROR(GetTpm())) {
		return gTpm->GetRandom(gTpm, (UINT32)len, buf);
	}
	return EFI_NOT_READY;
}

EFI_STATUS
RndTpmInit(
	IN DCS_RND* rnd,
	IN VOID* Context,
	IN UINTN ContextSize
	)
{
	ZeroMem(rnd, sizeof(DCS_RND));
	rnd->Type = RndTypeTpm;
	rnd->GetBytes = RndTpmGetBytes;
	rnd->Prepare = RndTpmPrepare;
	return rnd->Prepare(rnd);
}
#endif

//////////////////////////////////////////////////////////////////////////
// Random API
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
RndInit(
	IN UINTN   rndType,
	IN VOID*   Context,
	IN UINTN   ContextSize,
	OUT DCS_RND **rnd)
{
	if (rnd != NULL) {
		DCS_RND *rndTemp;
		rndTemp = (DCS_RND*)MEM_ALLOC(sizeof(DCS_RND));
		if (rndTemp != NULL) {
			EFI_STATUS res = EFI_NOT_FOUND;
			rndTemp->Type = (UINT32)rndType;
			switch (rndType) {
			case RndTypeFile:
				res = RndFileInit(rndTemp, Context, ContextSize);
				break;
			case RndTypeRDRand:
				res = RndRDRandInit(rndTemp, Context, ContextSize);
				break;
			case RndTypeDtrmHmacSha512:
				res = RndDtrmHmacSha512Init(rndTemp, Context, ContextSize);
				break;
			case RndTypeOpenSSL:
				res = RndOpenSSLInit(rndTemp, Context, ContextSize);
				break;
			case RndTypeTpm:
#ifdef CFG_RND_USE_TPM
				res = RndTpmInit(rndTemp, Context, ContextSize);
#else
				res = EFI_UNSUPPORTED;
#endif
				break;
			}
			if (EFI_ERROR(res)) {
				MEM_FREE(rndTemp);
				return res;
			}
			*rnd = rndTemp;
			return res;
		}
	}
	return EFI_NOT_READY;
}

EFI_STATUS
RndGetBytes(
	UINT8 *buf, 
	UINTN len)
{
	if (gRnd != NULL) {
		return gRnd->GetBytes(gRnd, buf, len);
	}
	return EFI_NOT_READY;
}

EFI_STATUS
RndPrepare() 
{
	if (gRnd != NULL) {
		return gRnd->Prepare(gRnd);
	}
	return EFI_NOT_READY;
}

UINT64 gRndHeaderSign = RND_HEADER_SIGN;

EFI_STATUS
RndSave(
	IN  DCS_RND         *rnd, 
	OUT DCS_RND_SAVED  **rndSaved
	) 
{
	EFI_STATUS res = EFI_NOT_READY;
	DCS_RND_SAVED    *RndSaved;
	UINT32 crc;
	if (rnd != NULL && rndSaved != NULL && rnd->Type != RndTypeFile && rnd->Type != RndTypeOpenSSL) {
		RndSaved = MEM_ALLOC(sizeof(DCS_RND_SAVED));
		if (RndSaved != NULL) {
			RndSaved->Size = sizeof(DCS_RND_SAVED);
			CopyMem(&RndSaved->State, &rnd->State, sizeof(DCS_RND_STATE));
			RndSaved->Type = rnd->Type;
			RndSaved->Sign = gRndHeaderSign;
			gST->RuntimeServices->GetTime(&RndSaved->SavedAt, NULL);
			res = gBS->CalculateCrc32(RndSaved, sizeof(DCS_RND_SAVED), &crc);
			if (EFI_ERROR(res)) {
				MEM_FREE(RndSaved);
				return res;
			}
			RndSaved->CRC = crc;
			*rndSaved = RndSaved;
		}
	}
	return res;
}

EFI_STATUS
RndLoad(
	IN DCS_RND_SAVED *rndSaved,
	OUT DCS_RND      **rndOut
	) {
	EFI_STATUS res = EFI_SUCCESS;
	UINT32 crc;
	UINT32 crcSaved;

	crcSaved = rndSaved->CRC;
	rndSaved->CRC = 0;
	res = gBS->CalculateCrc32(rndSaved, sizeof(DCS_RND_SAVED), &crc);
	if (EFI_ERROR(res) || crc != crcSaved || rndSaved->Sign != gRndHeaderSign) {
		return EFI_CRC_ERROR;
	}
	res = RndInit(rndSaved->Type, NULL, 0, rndOut);
	if (!EFI_ERROR(res)) {
		CopyMem(&((*rndOut)->State), &rndSaved->State, sizeof(DCS_RND_STATE));
	}
	return res;
}
