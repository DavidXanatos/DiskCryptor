#ifndef _ENC_DEC_
#define _ENC_DEC_

typedef void (*s_callback)(void*,void*,int);

int  dc_enable_sync_mode(dev_hook *hook);
int  dc_encrypt_start(wchar_t *dev_name, dc_pass *password, crypt_info *crypt);
int  dc_decrypt_start(wchar_t *dev_name, dc_pass *password);
int  dc_reencrypt_start(wchar_t *dev_name, dc_pass *password, crypt_info *crypt);
int  dc_send_sync_packet(wchar_t *dev_name, u32 type, void *param);
void dc_sync_all_encs();

typedef struct _sync_packet {
	LIST_ENTRY entry_list;
	u32        type;
	PIRP       irp;
	void      *param;
	KEVENT     sync_event;
	int        status;

} sync_packet;

#define S_OP_ENC_BLOCK  0
#define S_OP_DEC_BLOCK  1
#define S_OP_SYNC       2
#define S_OP_FINALIZE   3

#define S_INIT_NONE       0
#define S_INIT_ENC        1
#define S_INIT_DEC        2
#define S_CONTINUE_ENC    3
#define S_INIT_RE_ENC     4
#define S_CONTINUE_RE_ENC 5

#endif