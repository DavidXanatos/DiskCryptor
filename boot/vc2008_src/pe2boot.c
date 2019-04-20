#include <windows.h>
#include <stdio.h>
#include "defines.h"

#pragma pack (push, 1)

typedef struct _boot_mod {
	u32 mod_sign;    /* signature 'DCBM' */
	u32 raw_size;    /* raw size         */
	u32 virt_size;   /* virtual size     */
	u32 entry_rva;   /* entry point RVA  */
	u32 n_rels;      /* relocations count */
	u32 relocs[];    /* relocations array */

} boot_mod;

typedef struct _IMAGE_FIXUP_ENTRY {
	u16	offset:12;
	u16	type  :04;
} IMAGE_FIXUP_ENTRY, *PIMAGE_FIXUP_ENTRY;

#pragma pack (pop)

static int pe_save_relocs(void *image, u32 *relocs)
{
	IMAGE_DOS_HEADER      *d_head = image;
	IMAGE_NT_HEADERS      *n_head = addof(d_head, d_head->e_lfanew);
	u32                    n_rels = 0;
	IMAGE_BASE_RELOCATION *reloc;
	IMAGE_FIXUP_ENTRY     *fixup;
	u32                    re_rva, i;
	
	if ( (re_rva = n_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) == 0 ) {
		return 1;
	}
	for ( reloc = addof(d_head, re_rva); 
		  reloc->VirtualAddress != 0; reloc = addof(reloc, reloc->SizeOfBlock) )
	{
		for ( i = 0, fixup = addof(reloc, sizeof(IMAGE_BASE_RELOCATION)); 
			  i < (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2; i++, fixup++)
		{
			if (fixup->type == IMAGE_REL_BASED_HIGHLOW) {
				relocs[n_rels++] = reloc->VirtualAddress + fixup->offset;
			}
		}
	}
	return n_rels;	
}

static int pe2mod(wchar_t *in, wchar_t *out) 
{
	IMAGE_DOS_HEADER     *d_head;
	IMAGE_NT_HEADERS     *n_head;
	IMAGE_SECTION_HEADER *t_sect;
	boot_mod             *b_mod = NULL;
	HMODULE               image = NULL;
	u32                  *reloc = NULL;
	int                   resl  = 1;
	u32                   r_num, offs;
	HANDLE                h_out;
	u32                   i, found;
	u32                   code_off;
	u32                   bytes, n;
	u8                   *s_data;
	u32                   s_size;

	do
	{
		if ( (image = LoadLibraryEx(in, NULL, DONT_RESOLVE_DLL_REFERENCES)) == NULL ) {
			break;
		}
		d_head = pv(dSZ(image) & ~(PAGE_SIZE - 1));
		n_head = addof(d_head, d_head->e_lfanew);
		t_sect = IMAGE_FIRST_SECTION(n_head);
		found  = 0;

		/* find '.text' section */
		for (i = 0; i < n_head->FileHeader.NumberOfSections; i++, t_sect++) {
			if (_stricmp(t_sect->Name, ".text") == 0) {	found = 1; break; }
		}
		if (found == 0) {
			wprintf(L"Invalid PE image %s, section '.text' is not found\n", in); 
			break;
		}
		if ( (reloc = calloc(1, n_head->OptionalHeader.SizeOfImage)) == NULL ) {
			break;
		}
		if ( (b_mod = calloc(1, n_head->OptionalHeader.SizeOfImage)) == NULL ) {
			break;
		}
		if (r_num = pe_save_relocs(d_head, reloc)) 
		{
			/* save needed relocs */
			for (i = 0, n = 0; i < r_num; i++) 
			{
				if (in_reg(reloc[i], t_sect->VirtualAddress, t_sect->Misc.VirtualSize) != 0) {
					b_mod->relocs[n++] = reloc[i]; 
				}
			}
			b_mod->n_rels = n;
			code_off = _align(sizeof(boot_mod) + n * sizeof(u32), 16);			
		} else {
			code_off = _align(sizeof(boot_mod), 16);
		}
		s_data = addof(d_head, t_sect->VirtualAddress);
		s_size = t_sect->SizeOfRawData;

		/* find minimum section RAW size */
		for (i = t_sect->SizeOfRawData - 1; i != 0; i--, s_size--) {
			if (s_data[i] != 0) break;
		}
		b_mod->mod_sign  = 'DCBM';
		b_mod->raw_size  = s_size + code_off;
		b_mod->virt_size = t_sect->Misc.VirtualSize + code_off;
		b_mod->entry_rva = n_head->OptionalHeader.AddressOfEntryPoint - 
			t_sect->VirtualAddress + code_off;

		memcpy(addof(b_mod, code_off), s_data, s_size);

		/* rebase image and fix relocs */
		for (i = 0; i < b_mod->n_rels; i++)
		{
			offs = b_mod->relocs[i] - t_sect->VirtualAddress + code_off;			
			p32(addof(b_mod, offs))[0] -= n_head->OptionalHeader.ImageBase + 
				t_sect->VirtualAddress - code_off;
			b_mod->relocs[i] = offs;
		}
		h_out = CreateFile(
			out, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

		if (h_out != INVALID_HANDLE_VALUE) 
		{
			if (WriteFile(h_out, b_mod, b_mod->raw_size, &bytes, NULL) != 0) {
				wprintf(L"Boot module OK (Virtual size: %d, Raw size: %d)\n", b_mod->virt_size, b_mod->raw_size);				
				resl = 0;
			}
			CloseHandle(h_out);
		} else {
			wprintf(L"Can not write to %s", out);
		}
	} while (0);

	if (reloc != NULL) { free(reloc); }
	if (b_mod != NULL) { free(b_mod); }
	if (image != NULL) { FreeLibrary(image); }

	return resl;
}

int wmain(int argc, wchar_t *argv[])
{
	if (argc < 3) {
		wprintf(L"pe2boot [dll] [mod]  convert DLL to boot module\n");
		return 1;
	}
	return pe2mod(argv[1], argv[2]);
}