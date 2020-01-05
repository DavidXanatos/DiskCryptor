#ifndef _PRCENCRYPT_
#define _PRCENCRYPT_

#define WPAGE_ENC_ISO			0
#define WPAGE_ENC_FRMT			1
#define WPAGE_ENC_CONF			2
#define WPAGE_ENC_BOOT			3
#define WPAGE_ENC_PASS			4
#define WPAGE_ENC_PROGRESS		5

INT_PTR 
CALLBACK
_wizard_encrypt_dlg_proc(
		HWND	hwnd,
		UINT	message,
		WPARAM	wparam,
		LPARAM	lparam
	);


#endif