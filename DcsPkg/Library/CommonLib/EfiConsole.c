/** @file
EFI console helpers routines/wrappers

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov, Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Protocol/SimpleTextOut.h>
#include <Protocol/ConsoleControl.h>
#include <Protocol/Speaker.h>

UINTN gCELine = 0;

//////////////////////////////////////////////////////////////////////////
// Print
//////////////////////////////////////////////////////////////////////////

VOID
PrintBytes(
	IN UINT8* Data,
	IN UINTN Size)
{
	UINTN i;
	for (i = 0; i < Size; ++i) {
		UINTN val = Data[i];
		OUT_PRINT(L"%02X", val);
	}
}

/*
#define DUMP_MAX_LINE_LEN 1024
typedef struct _DUMP_STATE {
	CHAR8    line[DUMP_MAX_LINE_LEN];

} DUMP_STATE;

VOID
DumpBytes(
	IN UINT8* Data,
	IN UINT32 Size)
{
	UINT32 i;
	CHAR8 text[17];
	UINTN addr = 0;
	for (i = 0; i < Size; ++i) {
		if ((addr & 0x0F) == 0) {
			SetMem(text, sizeof(text) - 1, ' ');
			text[16] = 0;
			OUT_PRINT(L"%08X: ", addr);
		}
		UINT32 val = Data[i];
		OUT_PRINT(L"%02X ", val);
		if (val > 31 && val < 127) {
			text[i & 0x0F] = (CHAR8)(val & 0x0FF);
		}
		addr++;
		if ((addr & 0x0F) == 0) {
			OUT_PRINT(L"|%a|", text);
		}
	}
	if (addr & 0x0F) != 0) {
	}
}
*/

//////////////////////////////////////////////////////////////////////////
// Input
//////////////////////////////////////////////////////////////////////////
VOID 
FlushInputDelay(
	IN UINTN delay
	) 
{
   EFI_INPUT_KEY  key;
   EFI_EVENT      InputEvents[2];
   UINTN          EventIndex = 0;

   InputEvents[0] = gST->ConIn->WaitForKey;
   gBS->CreateEvent(EVT_TIMER, 0, (EFI_EVENT_NOTIFY)NULL, NULL, &InputEvents[1]);
   gBS->SetTimer(InputEvents[1], TimerPeriodic, delay);
   while (EventIndex == 0) {
      gBS->WaitForEvent(2, InputEvents, &EventIndex);
      if (EventIndex == 0) {
         gST->ConIn->ReadKeyStroke(gST->ConIn, &key);
      }
   }
   gBS->CloseEvent(InputEvents[1]);
}

VOID
FlushInput() {
	FlushInputDelay(1000000);
}

EFI_INPUT_KEY
KeyWait(
   CHAR16* Prompt,
   UINTN mDelay,
   UINT16 scanCode,
   UINT16 unicodeChar)
{
   EFI_INPUT_KEY  key;
   EFI_EVENT      InputEvents[2];
   UINTN          EventIndex;

   FlushInput();
   key.ScanCode = scanCode;
   key.UnicodeChar = unicodeChar;

   InputEvents[0] = gST->ConIn->WaitForKey;

   gBS->CreateEvent(EVT_TIMER, 0, (EFI_EVENT_NOTIFY)NULL, NULL, &InputEvents[1]);
   gBS->SetTimer(InputEvents[1], TimerPeriodic, 10000000);
   while (mDelay > 0) {
      OUT_PRINT(Prompt, mDelay);
      gBS->WaitForEvent(2, InputEvents, &EventIndex);
      if (EventIndex == 0) {
			if (EFI_ERROR(gST->ConIn->ReadKeyStroke(gST->ConIn, &key))) {
				continue;
			}
         break;
      }
      else {
         mDelay--;
      }
   }
   OUT_PRINT(Prompt, mDelay);
   gBS->CloseEvent(InputEvents[1]);
   return key;
}

EFI_INPUT_KEY 
GetKey(void) 
{
   EFI_INPUT_KEY key;
   UINTN EventIndex;
	EFI_STATUS res1;
	EFI_STATUS res2;
	do {
		res1 = gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &EventIndex);
		res2 = gST->ConIn->ReadKeyStroke(gST->ConIn, &key);
	} while (EFI_ERROR(res1) || EFI_ERROR(res2));
   return MapKeyboardKey(key);
}

VOID
ConsoleShowTip(
	IN CHAR16* tip,
	IN UINTN   delay)
{
	EFI_EVENT      InputEvents[2];
	UINTN          EventIndex = 0;
	UINTN          i = 0;
	EFI_INPUT_KEY  key;
	OUT_PRINT(L"%s", tip);

	// delay
	InputEvents[0] = gST->ConIn->WaitForKey;
	gBS->CreateEvent(EVT_TIMER, 0, (EFI_EVENT_NOTIFY)NULL, NULL, &InputEvents[1]);
	gBS->SetTimer(InputEvents[1], TimerPeriodic, delay);
	gBS->WaitForEvent(2, InputEvents, &EventIndex);
	if (EventIndex == 0) {
		gST->ConIn->ReadKeyStroke(gST->ConIn, &key);
	}

	// remove tip
	for (i = 0; i < StrLen(tip); ++i) {
		OUT_PRINT(L"\b \b");
	}
}


VOID 
GetLine (
   UINTN    *length, 
   CHAR16   *line, 
   CHAR8    *asciiLine,
   UINTN    line_max,
   UINT8    show)
{
   EFI_INPUT_KEY key;
   UINT32 count = 0;

   do {
      key = GetKey();
		// Remove dirty chars 0.1s
		FlushInputDelay(100000);

      if ((count >= line_max &&
         key.UnicodeChar != CHAR_BACKSPACE) ||
         key.UnicodeChar == CHAR_NULL ||
         key.UnicodeChar == CHAR_TAB  ||
         key.UnicodeChar == CHAR_LINEFEED ||
         key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
            continue;
      }

      if (count == 0 && key.UnicodeChar == CHAR_BACKSPACE) {
         continue;
      } else if (key.UnicodeChar == CHAR_BACKSPACE) {
         OUT_PRINT(L"\b \b");
         if (line != NULL) line[--count] = '\0';
         if (asciiLine != NULL) asciiLine[--count] = '\0';
         continue;
      }

      // check size of line
      if (count < line_max - 1) {
         if (show) {
            OUT_PRINT(L"%c", key.UnicodeChar);
         }
         else {
            OUT_PRINT(L"*");
         }
         // save char
         if (line != NULL) line[count++] = key.UnicodeChar;
         if (asciiLine != NULL) asciiLine[count++] = (CHAR8)key.UnicodeChar;
      }
   } while (key.UnicodeChar != CHAR_CARRIAGE_RETURN);

   OUT_PRINT(L"\n");
   if (length != NULL) *length = count;
   // Set end of line
   if (line != NULL) line[count] = '\0';
   if (asciiLine != NULL) asciiLine[count] = '\0';
}

int
AskAsciiString(
   CHAR8* prompt,
   CHAR8* str,
   UINTN max_len,
   UINT8 visible,
	CHAR8* defStr)
{
   UINTN       len = 0;
	if (defStr == NULL) {
		OUT_PRINT(L"%a", prompt);
	} else {
		OUT_PRINT(L"[%a] %a", defStr, prompt);
	}
	GetLine(&len, NULL, str, max_len, visible);
	if (defStr != NULL && len == 0) {
		AsciiStrCpyS(str, max_len, defStr);
		len = AsciiStrLen(str);
	}
   return (UINT32)len;
}

int
AskInt(
   CHAR8* prompt,
   UINT8 visible)
{
   CHAR16      buf[32];
   UINTN       len = 0;
	OUT_PRINT(L"%a", prompt);
	GetLine(&len, buf, NULL, sizeof(buf) / 2, visible);
   return (UINT32)StrDecimalToUintn(buf);
}

UINT8
AskConfirm(
   CHAR8* prompt,
   UINT8 visible)
{
   CHAR16      buf[2];
   UINTN       len = 0;
	OUT_PRINT(L"%a", prompt);
	GetLine(&len, buf, NULL, sizeof(buf) / 2, visible);
   return (buf[0] == 'y') || (buf[0] == 'Y') ? 1 : 0;
}

UINT64
AskUINT64(
	IN char* prompt,
	IN UINT64 def)
{
	CHAR16      buf[128];
	UINTN       len = 0;
	OUT_PRINT(L"[%lld] %a", def, prompt);
	GetLine(&len, buf, NULL, sizeof(buf) / 2, 1);
	return (len == 0) ? def : (UINT64)StrDecimalToUint64(buf);
}

UINT64
AskHexUINT64(
	IN char* prompt,
	IN UINT64 def)
{
	CHAR16      buf[128];
	UINTN       len = 0;
	OUT_PRINT(L"[0x%llx] %a", def, prompt);
	GetLine(&len, buf, NULL, sizeof(buf) / 2, 1);
	return (len == 0) ? def : (UINT64)StrHexToUint64(buf);
}

UINTN
AskUINTN(
	IN char* prompt,
	IN UINTN def)
{
	CHAR16      buf[128];
	UINTN       len = 0;
	OUT_PRINT(L"[%d] %a", def, prompt);
	GetLine(&len, buf, NULL, sizeof(buf) / 2, 1);
	return (len == 0) ? def : StrDecimalToUintn(buf);
}

EFI_STATUS
ConsoleGetOutput(
	IN EFI_HANDLE handle,
	OUT   EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL**	io
	) {
	return gBS->HandleProtocol(handle, &gEfiSimpleTextOutProtocolGuid, (VOID**)io);
}

//////////////////////////////////////////////////////////////////////////
// Ascii converters
//////////////////////////////////////////////////////////////////////////
BOOLEAN
AsciiHexToDigit(
	OUT UINT8  *b,
	IN  CHAR8  *str
	)
{
	CHAR8 ch;
	ch = str[0];
	if (ch >= '0' && ch <= '9') {
		*b = ch - '0';
		return TRUE;
	}
	else {
		ch = ch & ~0x20;
		if (ch >= 'A' && ch <= 'F') {
			*b = ch - 'A' + 10;
			return TRUE;
		}
	}
	return FALSE;
}

BOOLEAN
AsciiHexToByte(
	OUT UINT8  *b,
	IN  CHAR8  *str
	)
{
	UINT8 low = 0;
	UINT8 high = 0;
	BOOLEAN res;
	res = AsciiHexToDigit(&high, str);
	res = res && AsciiHexToDigit(&low, str + 1);
	*b = low | high << 4;
	return res;
}

BOOLEAN
DcsAsciiStrToGuid(
	OUT EFI_GUID  *guid,
	IN  CHAR8     *str
	)
{
	UINT8 b[16];
	BOOLEAN res = TRUE;
	int i;
	CHAR8* pos = str;
	if (guid == NULL || str == NULL) return FALSE;
	for (i = 0; i < 16; ++i) {
		if (*pos == '-') pos++;
		res = res && AsciiHexToByte(&b[i], pos);
		pos += 2;
		if (!res) return FALSE;
	}
	guid->Data1 = b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3];
	guid->Data2 = b[4] << 8 | b[5];
	guid->Data3 = b[6] << 8 | b[7];
	CopyMem(&guid->Data4, &b[8], 8);
	return res;
}

BOOLEAN
AsciiHexToBytes(
	OUT UINT8  *b,
	IN  UINTN  *bytesLen,
	IN  CHAR8  *str
	)
{
	UINT8 low = 0;
	UINT8 high = 0;
	BOOLEAN res = TRUE;
	UINTN cnt = 0;
	UINTN len = 0;
	CHAR8  *pos = str;
	if (b == NULL || str == NULL || bytesLen == NULL) return FALSE;
	if (*bytesLen == 0) return TRUE;
	len = AsciiStrLen(str);
	if (len == 0) return TRUE;
	if (len > 2 && str[0] == '0' && str[1] == 'x') {
		pos += 2;
	}
	if ((len & 1) == 0) {
		res = AsciiHexToDigit(&high, pos++);
	}
	res = res && AsciiHexToDigit(&low, pos++);
	*b = low | high << 4;
	b++;
	cnt++;
	while (res && (cnt < *bytesLen) && (*pos != 0)) {
		res = AsciiHexToDigit(&high, pos++);
		res = res && AsciiHexToDigit(&low, pos++);
		*b = low | high << 4;
		b++;
		cnt++;
	}
	*bytesLen = cnt;
	return res;
}

BOOLEAN
DcsStrHexToBytes(
	OUT UINT8  *b,
	IN  UINTN  *bytesLen,
	IN  CHAR16  *str
	)
{
	UINT8 low = 0;
	UINT8 high = 0;
	BOOLEAN res = TRUE;
	UINTN cnt = 0;
	UINTN len = 0;
	CHAR16  *pos = str;
	if (b == NULL || str == NULL || bytesLen == NULL) return FALSE;
	if (*bytesLen == 0) return TRUE;
	len = StrLen(str);
	if (len == 0) return TRUE;
	if (len > 2 && str[0] == '0' && str[1] == 'x') {
		pos += 2;
	}
	if ((len & 1) == 0) {
		res = AsciiHexToDigit(&high, (CHAR8*)pos);
		pos++;
	}
	res = res && AsciiHexToDigit(&low, (CHAR8*)pos);
	pos++;
	*b = low | high << 4;
	b++;
	cnt++;
	while (res && (cnt < *bytesLen) && (*pos != 0)) {
		res = AsciiHexToDigit(&high, (CHAR8*)pos);
		pos++;
		res = res && AsciiHexToDigit(&low, (CHAR8*)pos);
		pos++;
		*b = low | high << 4;
		b++;
		cnt++;
	}
	*bytesLen = cnt;
	return res;
}

//////////////////////////////////////////////////////////////////////////
// Console menu
//////////////////////////////////////////////////////////////////////////

PMENU_ITEM
DcsMenuAppend(
	IN PMENU_ITEM  menu,
	IN CHAR16     *text,
	IN CHAR16     select,
	IN MENU_ACTION action,
	IN VOID*       actionContext
	) {
	PMENU_ITEM item;
	item = (PMENU_ITEM)MEM_ALLOC(sizeof(MENU_ITEM));
	if (item == NULL) return item;
	item->Action = action;
	item->Context = actionContext;
	StrCat(item->Text, text);
	item->Select = select;
	if (menu != NULL) {
		menu->Next = item;
	}
	return item;
}

VOID
DcsMenuPrint(
	IN  PMENU_ITEM head
	)
{
	PMENU_ITEM menu;
	UINTN i = 0;
	menu = head;
	while (menu != NULL) {
		OUT_PRINT(L"%H%c%N) %s\n", menu->Select, &menu->Text);
		i++;
		if (i == 22) {
			ConsoleShowTip(L"Pause 60s", 60000000);
			i = 0;
		}
		menu = menu->Next;
	}
	OUT_PRINT(L"[");
	menu = head;
	while (menu != NULL) {
		OUT_PRINT(L"%H%c%N", menu->Select);
		menu = menu->Next;
	}
	OUT_PRINT(L"]:");
}


//////////////////////////////////////////////////////////////////////////
// Console control
//////////////////////////////////////////////////////////////////////////

EFI_HANDLE* gConsoleControlHandles = NULL;
UINTN       gConsoleControlCount = 0;

EFI_STATUS
InitConsoleControl() {
	EFI_STATUS	res;
	// Init Console control if supported
	EFI_GUID   gConsoleControlProtocolGuid = EFI_CONSOLE_CONTROL_PROTOCOL_GUID;
	EFI_CONSOLE_CONTROL_PROTOCOL*	ConsoleControl;
	res = EfiGetHandles(ByProtocol, &gConsoleControlProtocolGuid, 0, &gConsoleControlHandles, &gConsoleControlCount);
	if (gConsoleControlCount > 0) {
		res = gBS->HandleProtocol(gConsoleControlHandles[0], &gConsoleControlProtocolGuid, (VOID**)&ConsoleControl);
		if (!EFI_ERROR(res)) {
			// Unlock graphics
			ConsoleControl->SetMode(ConsoleControl, EfiConsoleControlScreenGraphics);
		}
	}
	return res;
}
