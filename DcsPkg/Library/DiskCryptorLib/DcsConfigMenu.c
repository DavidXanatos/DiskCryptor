/** @file
DiskCryptor configuration menu

Copyright (c) 2026. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU General Public License, version 3.0 (GPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/GPL-3.0
**/

#include <Uefi.h>
#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <DcsConfig.h>
#include "DcsConfigMenu.h"

extern int     gKeyboardLayout;
extern int     gDCryptHwCrypto;

#define CFG_MENU_ITEMS  3
#define CFG_VALUE_COL   22  // column where "< value >" starts
#define CFG_VALUE_WIDTH 10  // fixed width for the value text between < >

typedef struct _CFG_MENU_ITEM {
	CHAR16  *Label;
	INT32    Min;
	INT32    Max;
	INT32    Value;
	CHAR16 **ValueNames;  // NULL for numeric display
	INT32    ValueCount;   // number of named values
} CFG_MENU_ITEM;

static CHAR16 *gKbLayoutNames[] = {
	L"QWERTY",
	L"QWERTZ"
};

static CHAR16 *gBoolNames[] = {
	L"False",
	L"True"
};

// Draw a single menu item line at the given screen row.
static VOID
CfgMenuDrawItem(
	CFG_MENU_ITEM *Item,
	INT32          Row,
	BOOLEAN        Selected
)
{
	INT32 i;
	CHAR16 valBuf[CFG_VALUE_WIDTH + 1];
	INT32 len;

	gST->ConOut->SetCursorPosition(gST->ConOut, 0, Row);

	if (Selected)
		OUT_PRINT(L"%V> ");
	else
		OUT_PRINT(L"  ");

	OUT_PRINT(L"%-20s", Item->Label);

	// Format value into fixed-width buffer, left-justified, space-padded
	if (Item->ValueNames != NULL && Item->Value < Item->ValueCount) {
		len = (INT32)StrLen(Item->ValueNames[Item->Value]);
		for (i = 0; i < CFG_VALUE_WIDTH; i++)
			valBuf[i] = (i < len) ? Item->ValueNames[Item->Value][i] : L' ';
	} else {
		// Format the integer manually into the buffer
		CHAR16 numBuf[12];
		INT32 val = Item->Value;
		INT32 pos = 0;
		if (val == 0) {
			numBuf[pos++] = L'0';
		} else {
			// Build digits in reverse
			CHAR16 tmp[12];
			INT32 tpos = 0;
			while (val > 0) {
				tmp[tpos++] = L'0' + (CHAR16)(val % 10);
				val /= 10;
			}
			// Reverse into numBuf
			while (tpos > 0)
				numBuf[pos++] = tmp[--tpos];
		}
		len = pos;
		for (i = 0; i < CFG_VALUE_WIDTH; i++)
			valBuf[i] = (i < len) ? numBuf[i] : L' ';
	}
	valBuf[CFG_VALUE_WIDTH] = L'\0';

	OUT_PRINT(L"< %s >", valBuf);

	if (Selected)
		OUT_PRINT(L"%N");
}

// Redraw only the value portion of a single item.
static VOID
CfgMenuDrawValue(
	CFG_MENU_ITEM *Item,
	INT32          Row,
	BOOLEAN        Selected
)
{
	// Reposition to value column and redraw from there
	// Redrawing the full line is simplest to keep highlight consistent
	CfgMenuDrawItem(Item, Row, Selected);
}

VOID
DcsShowHelp(
	VOID
)
{
	gST->ConOut->ClearScreen(gST->ConOut);
	OUT_PRINT(L"--- Help ---\r\n");
	OUT_PRINT(L"\r\n");
	OUT_PRINT(L"  Enter       Submit password\r\n");
	OUT_PRINT(L"  Esc         Cancel\r\n");
	OUT_PRINT(L"  F1          Show this help\r\n");
	OUT_PRINT(L"  F5          Toggle password visibility\r\n");
	OUT_PRINT(L"  F6          Configuration menu\r\n");
	OUT_PRINT(L"\r\n");
	OUT_PRINT(L"  Left/Right  Move cursor\r\n");
	OUT_PRINT(L"  Home/End    Jump to start/end\r\n");
	OUT_PRINT(L"  Delete      Delete character\r\n");
	OUT_PRINT(L"  Insert      Insert space\r\n");
	OUT_PRINT(L"\r\n");
	OUT_PRINT(L"------------\r\n");
	OUT_PRINT(L"Press any key to return...\r\n");

	GetKey();
	FlushInputDelay(100000);
	gST->ConOut->ClearScreen(gST->ConOut);
}

BOOLEAN
DcsConfigMenuShow(
	VOID
)
{
	EFI_INPUT_KEY key;
	INT32         selected = 0;
	INT32         prev;
	INT32         baseRow;
	INT32         i;
	CFG_MENU_ITEM items[CFG_MENU_ITEMS];

	// Keyboard Layout
	items[0].Label      = L"Keyboard Layout";
	items[0].Min        = 0;
	items[0].Max        = 1;
	items[0].Value      = gKeyboardLayout;
	items[0].ValueNames = gKbLayoutNames;
	items[0].ValueCount = 2;

	// Hardware Crypto
	items[1].Label      = L"Hardware Crypto";
	items[1].Min        = 0;
	items[1].Max        = 1;
	items[1].Value      = gDCryptHwCrypto ? 1 : 0;
	items[1].ValueNames = gBoolNames;
	items[1].ValueCount = 2;

	// Debug Mode
	items[2].Label      = L"Debug Mode";
	items[2].Min        = 0;
	items[2].Max        = 1;
	items[2].Value      = gConfigDebug ? 1 : 0;
	items[2].ValueNames = gBoolNames;
	items[2].ValueCount = 2;

	// --- Initial full draw ---
	gST->ConOut->ClearScreen(gST->ConOut);
	OUT_PRINT(L"--- Configuration ---\r\n");

	baseRow = gST->ConOut->Mode->CursorRow;

	for (i = 0; i < CFG_MENU_ITEMS; i++) {
		CfgMenuDrawItem(&items[i], baseRow + i, (i == selected));
		OUT_PRINT(L"\r\n");
	}

	OUT_PRINT(L"---------------------\r\n");
	OUT_PRINT(L"Up/Down:select  Left/Right:change  Enter:apply  Esc:cancel\r\n");

	gST->ConOut->EnableCursor(gST->ConOut, FALSE);

	// --- Input loop: only redraw what changed ---
	for (;;) {
		key = GetKey();
		FlushInputDelay(100000);

		if (key.ScanCode == SCAN_ESC) {
			gST->ConOut->EnableCursor(gST->ConOut, TRUE);
			gST->ConOut->ClearScreen(gST->ConOut);
			return FALSE;
		}

		if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
			gKeyboardLayout   = items[0].Value;
			gDCryptHwCrypto   = items[1].Value;
			gConfigDebug      = items[2].Value ? TRUE : FALSE;
			gST->ConOut->EnableCursor(gST->ConOut, TRUE);
			gST->ConOut->ClearScreen(gST->ConOut);
			return TRUE;
		}

		if (key.ScanCode == SCAN_UP) {
			if (selected > 0) {
				prev = selected;
				selected--;
				CfgMenuDrawItem(&items[prev], baseRow + prev, FALSE);
				CfgMenuDrawItem(&items[selected], baseRow + selected, TRUE);
			}
		}

		if (key.ScanCode == SCAN_DOWN) {
			if (selected < CFG_MENU_ITEMS - 1) {
				prev = selected;
				selected++;
				CfgMenuDrawItem(&items[prev], baseRow + prev, FALSE);
				CfgMenuDrawItem(&items[selected], baseRow + selected, TRUE);
			}
		}

		if (key.ScanCode == SCAN_RIGHT) {
			if (items[selected].Value < items[selected].Max) {
				items[selected].Value++;
				CfgMenuDrawValue(&items[selected], baseRow + selected, TRUE);
			}
		}

		if (key.ScanCode == SCAN_LEFT) {
			if (items[selected].Value > items[selected].Min) {
				items[selected].Value--;
				CfgMenuDrawValue(&items[selected], baseRow + selected, TRUE);
			}
		}
	}
}
