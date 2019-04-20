#ifndef _LINKLIST_
#define _LINKLIST_

typedef struct _list_entry 
{
   struct _list_entry *flink;
   struct _list_entry *blink;

} list_entry;

#define contain_record(address, type, field) ( \
		(type *)( p8(address) - (size_t)(&((type *)0)->field)) \
	)

#define _init_list_head(head) ( \
		(head)->flink = (head)->blink = (head) \
	)

#define _is_list_empty(head) ( \
		(head)->flink == (head) \
	)

#define _remove_entry_list(entry) { \
		list_entry *_ex_blink; \
	    list_entry *_ex_flink; \
		_ex_flink = (entry)->flink; \
	    _ex_blink = (entry)->blink; \
		_ex_blink->flink = _ex_flink; \
	    _ex_flink->blink = _ex_blink; \
	}

#define _remove_head_list(head) \
		(head)->flink; \
		{ \
			_remove_entry_list((head)->flink) \
		}

#define _insert_tail_list(head,entry) { \
		list_entry *_ex_blink; \
	    list_entry *_ex_head; \
		_ex_head  = (head); \
	    _ex_blink = _ex_head->blink; \
		(entry)->flink = _ex_head; \
	    (entry)->blink = _ex_blink; \
		_ex_blink->flink = (entry); \
	    _ex_head->blink = (entry); \
    }

#define _insert_head_list(head,entry) { \
	    list_entry *_ex_flink; \
		list_entry *_ex_head; \
	    _ex_head = (head); \
		_ex_flink = _ex_head->flink; \
	    (entry)->flink = _ex_flink; \
		(entry)->blink = _ex_head; \
	    _ex_flink->blink = (entry); \
		_ex_head->flink = (entry); \
    }

#endif

