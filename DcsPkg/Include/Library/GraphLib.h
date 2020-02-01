/** @file
Graph library

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials are licensed and made available 
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#ifndef __GRAPHLIB_H__
#define __GRAPHLIB_H__

#include <Uefi.h>
#include <Protocol/GraphicsOutput.h>

//////////////////////////////////////////////////////////////////////////
// Graph
//////////////////////////////////////////////////////////////////////////

extern EFI_HANDLE* gGraphHandles;
extern UINTN       gGraphCount;
extern EFI_GRAPHICS_OUTPUT_PROTOCOL*	gGraphOut;

EFI_STATUS
InitGraph();

EFI_STATUS
GraphGetIO(
	IN    EFI_HANDLE								Handle,
	OUT   EFI_GRAPHICS_OUTPUT_PROTOCOL**	io
	);

EFI_STATUS
GraphGetModeInfo(
	IN    UINTN mode,
	OUT   EFI_GRAPHICS_OUTPUT_MODE_INFORMATION **info,
	OUT	UINTN* szInfo
	);

typedef struct _RECT {
	UINT32 left;
	UINT32 top;
	UINT32 right;
	UINT32 bottom;
} RECT, *PRECT;

#pragma pack(1)
typedef struct {
	UINT32   Width;
	UINT32   Height;
	RECT     Dirty;
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL	 Pixels[0];
} BLT_HEADER;
#pragma pack()

enum DRAW_OPERATION {
	DrawOpSet = 0,
	DrawOpOr,
	DrawOpXor,
	DrawOpClear,
	DrawOpAlpha
};

typedef struct _DRAW_CONTEXT {
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL Color;
	UINT32	Op;
	UINT32	DashLine;
	UINT32	Alpha; //< 0..255
	EFI_GRAPHICS_OUTPUT_BLT_PIXEL AlphaColor;
	INT32*		Brush;		// brush points(default 1)
} DRAW_CONTEXT, *PDRAW_CONTEXT;

extern DRAW_CONTEXT	gDrawContext;
extern EFI_GRAPHICS_OUTPUT_BLT_PIXEL gColorBlack;
extern EFI_GRAPHICS_OUTPUT_BLT_PIXEL gColorWhite;
extern EFI_GRAPHICS_OUTPUT_BLT_PIXEL gColorBlue;
extern EFI_GRAPHICS_OUTPUT_BLT_PIXEL gColorGreen;
extern EFI_GRAPHICS_OUTPUT_BLT_PIXEL gColorRed;
extern EFI_GRAPHICS_OUTPUT_BLT_PIXEL gColorGray;
extern INT32 gBrush3[5 * 2];

EFI_STATUS
ScreenGetSize(
	OUT UINTN     *Height,
	OUT UINTN     *Width
	);

EFI_STATUS ScreenFillRect(
	IN EFI_GRAPHICS_OUTPUT_BLT_PIXEL *color,
	IN UINTN                         x,
	IN UINTN                         y,
	IN UINTN                         width,
	IN UINTN                         height
	);

EFI_STATUS ScreenDrawBlt(
	IN BLT_HEADER *blt,
	IN UINTN   x,
	IN UINTN   y
	);

EFI_STATUS
ScreenSaveBlt(
	OUT BLT_HEADER **bltScreen
	);

EFI_STATUS ScreenUpdateDirty(
	IN BLT_HEADER *blt
	);

EFI_STATUS
BltDrawBlt(
	IN OUT BLT_HEADER* canvas,
	IN BLT_HEADER* blt,
	IN UINTN x,
	IN UINTN y
	);

EFI_STATUS
RectMarkDirty(
	IN OUT PRECT rect,
	IN UINTN x,
	IN UINTN y
	);

EFI_STATUS
BltPoint(
	IN BLT_HEADER* blt,
	IN PDRAW_CONTEXT draw,
	IN UINTN x,
	IN UINTN y
	);

VOID
BltLine(
	IN BLT_HEADER* blt,
	IN PDRAW_CONTEXT draw,
	IN INT32 x0,
	IN INT32 y0,
	IN INT32 x1,
	IN INT32 y1);

VOID
BltBox(
	IN BLT_HEADER* blt,
	IN PDRAW_CONTEXT draw,
	IN INT32 x0,
	IN INT32 y0,
	IN INT32 x1,
	IN INT32 y1);

VOID
BltCircle(
	IN BLT_HEADER* blt,
	IN PDRAW_CONTEXT draw,
	IN INT32 xm,
	IN INT32 ym,
	IN INT32 r,
	IN BOOLEAN fill);

VOID
BltText(
	IN BLT_HEADER* blt,
	IN PDRAW_CONTEXT draw,
	IN INT32 x,
	IN INT32 y,
	IN INT32 scale, // 0..256 reduce 256... enlarge
	IN CONST VOID *text,
	IN BOOLEAN wide);


EFI_STATUS
BmpGetSize(
	IN const unsigned char*      BmpImage,
	IN UINTN      BmpImageSize,
	OUT UINTN     *Height,
	OUT UINTN     *Width
	);

EFI_STATUS
BmpToBlt(
	IN CONST VOID      *BmpImage,
	IN  UINTN     BmpImageSize,
	OUT BLT_HEADER **blt
	);

VOID
BltFill(
	IN BLT_HEADER* blt,
	IN EFI_GRAPHICS_OUTPUT_BLT_PIXEL	fill,
	IN INT32 x0,
	IN INT32 y0,
	IN INT32 x1,
	IN INT32 y1
	);

#endif