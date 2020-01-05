#include <windows.h>
#ifdef SMALL_CODE
	#include "sha512_pkcs5_2_small.h"
#else
	#include "sha512_pkcs5_2.h"
#endif

static const struct {
  int          i_count;
  const char  *password;
  const char  *salt;
  int          dklen;
  const char  *key;
} pkcs5_vectors[] = {
	{ 5, "password", "\x12\x34\x56\x78", 4, "\x13\x64\xae\xf8" },
	{ 5, "password", "\x12\x34\x56\x78", 144, "\x13\x64\xae\xf8\x0d\xf5\x57\x6c\x30\xd5\x71\x4c\xa7\x75\x3f"
	"\xfd\x00\xe5\x25\x8b\x39\xc7\x44\x7f\xce\x23\x3d\x08\x75\xe0\x2f\x48\xd6\x30\xd7\x00\xb6\x24\xdb\xe0\x5a\xd7\x47\xef\x52"
	"\xca\xa6\x34\x83\x47\xe5\xcb\xe9\x87\xf1\x20\x59\x6a\xe6\xa9\xcf\x51\x78\xc6\xb6\x23\xa6\x74\x0d\xe8\x91\xbe\x1a\xd0\x28"
	"\xcc\xce\x16\x98\x9a\xbe\xfb\xdc\x78\xc9\xe1\x7d\x72\x67\xce\xe1\x61\x56\x5f\x96\x68\xe6\xe1\xdd\xf4\xbf\x1b\x80\xe0\x19"
	"\x1c\xf4\xc4\xd3\xdd\xd5\xd5\x57\x2d\x83\xc7\xa3\x37\x87\xf4\x4e\xe0\xf6\xd8\x6d\x65\xdc\xa0\x52\xa3\x13\xbe\x81\xfc\x30"
	"\xbe\x7d\x69\x58\x34\xb6\xdd\x41\xc6" },
	// test vectors from http://stackoverflow.com/questions/15593184/pbkdf2-hmac-sha-512-test-vectors
	{ // Long Test 1a 1 iter 64 outputbytes Len19pw Len19sa
		1, "passDATAb00AB7YxDTT", "saltKEYbcTcXHCBxtjD", 64,
			"\xCB\xE6\x08\x8A\xD4\x35\x9A\xF4\x2E\x60\x3C\x2A\x33\x76\x0E\xF9"
			"\xD4\x01\x7A\x7B\x2A\xAD\x10\xAF\x46\xF9\x92\xC6\x60\xA0\xB4\x61"
			"\xEC\xB0\xDC\x2A\x79\xC2\x57\x09\x41\xBE\xA6\xA0\x8D\x15\xD6\x88"
			"\x7E\x79\xF3\x2B\x13\x2E\x1C\x13\x4E\x95\x25\xEE\xDD\xD7\x44\xFA"
	},
	{ // Long Test 1b 100000 iter 64 outputbytes Len19pw Len19sa
		100000,	"passDATAb00AB7YxDTT", "saltKEYbcTcXHCBxtjD", 64,
			"\xAC\xCD\xCD\x87\x98\xAE\x5C\xD8\x58\x04\x73\x90\x15\xEF\x2A\x11"
			"\xE3\x25\x91\xB7\xB7\xD1\x6F\x76\x81\x9B\x30\xB0\xD4\x9D\x80\xE1"
			"\xAB\xEA\x6C\x98\x22\xB8\x0A\x1F\xDF\xE4\x21\xE2\x6F\x56\x03\xEC"
			"\xA8\xA4\x7A\x64\xC9\xA0\x04\xFB\x5A\xF8\x22\x9F\x76\x2F\xF4\x1F"
	},
	{ // Long Test 2a 1 iter 64 outputbytes Len20pw Len20sa
		1, "passDATAb00AB7YxDTTl", "saltKEYbcTcXHCBxtjD2", 64,
			"\x8E\x50\x74\xA9\x51\x3C\x1F\x15\x12\xC9\xB1\xDF\x1D\x8B\xFF\xA9"
			"\xD8\xB4\xEF\x91\x05\xDF\xC1\x66\x81\x22\x28\x39\x56\x0F\xB6\x32"
			"\x64\xBE\xD6\xAA\xBF\x76\x1F\x18\x0E\x91\x2A\x66\xE0\xB5\x3D\x65"
			"\xEC\x88\xF6\xA1\x51\x9E\x14\x80\x4E\xBA\x6D\xC9\xDF\x13\x70\x07"
	},
	{ // Long Test 2b 100000 iter 64 outputbytes Len20pw Len20sa
		100000, "passDATAb00AB7YxDTTl", "saltKEYbcTcXHCBxtjD2", 64,
			"\x59\x42\x56\xB0\xBD\x4D\x6C\x9F\x21\xA8\x7F\x7B\xA5\x77\x2A\x79"
			"\x1A\x10\xE6\x11\x06\x94\xF4\x43\x65\xCD\x94\x67\x0E\x57\xF1\xAE"
			"\xCD\x79\x7E\xF1\xD1\x00\x19\x38\x71\x90\x44\xC7\xF0\x18\x02\x66"
			"\x97\x84\x5E\xB9\xAD\x97\xD9\x7D\xE3\x6A\xB8\x78\x6A\xAB\x50\x96"
	},
	{ // Long Test 3a 1 iter 64 outputbytes Len21pw Len21sa
		1, "passDATAb00AB7YxDTTlR", "saltKEYbcTcXHCBxtjD2P", 64,
			"\xA6\xAC\x8C\x04\x8A\x7D\xFD\x7B\x83\x8D\xA8\x8F\x22\xC3\xFA\xB5"
			"\xBF\xF1\x5D\x7C\xB8\xD8\x3A\x62\xC6\x72\x1A\x8F\xAF\x69\x03\xEA"
			"\xB6\x15\x2C\xB7\x42\x10\x26\xE3\x6F\x2F\xFE\xF6\x61\xEB\x43\x84"
			"\xDC\x27\x64\x95\xC7\x1B\x5C\xAB\x72\xE1\xC1\xA3\x87\x12\xE5\x6B"
	},
	{ // Long Test 3b 100000 iter 64 outputbytes Len21pw Len21sa
		100000, "passDATAb00AB7YxDTTlR", "saltKEYbcTcXHCBxtjD2P", 64,
			"\x94\xFF\xC2\xB1\xA3\x90\xB7\xB8\xA9\xE6\xA4\x49\x22\xC3\x30\xDB"
			"\x2B\x19\x3A\xDC\xF0\x82\xEE\xCD\x06\x05\x71\x97\xF3\x59\x31\xA9"
			"\xD0\xEC\x0E\xE5\xC6\x60\x74\x4B\x50\xB6\x1F\x23\x11\x9B\x84\x7E"
			"\x65\x8D\x17\x9A\x91\x48\x07\xF4\xB8\xAB\x8E\xB9\x50\x5A\xF0\x65"
	},
	{ // Long Test 4a 1 iter 64 outputbytes Len63pw Len63sa
		1,
		"passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE5",
		"saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJe",
		64,
		"\xE2\xCC\xC7\x82\x7F\x1D\xD7\xC3\x30\x41\xA9\x89\x06\xA8\xFD\x7B"
		"\xAE\x19\x20\xA5\x5F\xCB\x8F\x83\x16\x83\xF1\x4F\x1C\x39\x79\x35"
		"\x1C\xB8\x68\x71\x7E\x5A\xB3\x42\xD9\xA1\x1A\xCF\x0B\x12\xD3\x28"
		"\x39\x31\xD6\x09\xB0\x66\x02\xDA\x33\xF8\x37\x7D\x1F\x1F\x99\x02"
	},
	{ // Long Test 4b 100000 iter 64 outputbytes Len63pw Len63sa
		100000,
		"passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE5",
		"saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJe",
		64,
		"\x07\x44\x74\x01\xC8\x57\x66\xE4\xAE\xD5\x83\xDE\x2E\x6B\xF5\xA6"
		"\x75\xEA\xBE\x4F\x36\x18\x28\x1C\x95\x61\x6F\x4F\xC1\xFD\xFE\x6E"
		"\xCB\xC1\xC3\x98\x27\x89\xD4\xFD\x94\x1D\x65\x84\xEF\x53\x4A\x78"
		"\xBD\x37\xAE\x02\x55\x5D\x94\x55\xE8\xF0\x89\xFD\xB4\xDF\xB6\xBB"
	},
	{ // Long Test 5a 1 iter 64 outputbytes Len64pw Len64sa
		1,
		"passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57",
		"saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJem",
		64,
		"\xB0\x29\xA5\x51\x11\x7F\xF3\x69\x77\xF2\x83\xF5\x79\xDC\x70\x65"
		"\xB3\x52\x26\x6E\xA2\x43\xBD\xD3\xF9\x20\xF2\x4D\x4D\x14\x1E\xD8"
		"\xB6\xE0\x2D\x96\xE2\xD3\xBD\xFB\x76\xF8\xD7\x7B\xA8\xF4\xBB\x54"
		"\x89\x96\xAD\x85\xBB\x6F\x11\xD0\x1A\x01\x5C\xE5\x18\xF9\xA7\x17"
	},
	{ // Long Test 5b 100000 iter 64 outputbytes Len64pw Len64sa
		100000,
		"passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57",
		"saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJem",
		64,
		"\x31\xF5\xCC\x83\xED\x0E\x94\x8C\x05\xA1\x57\x35\xD8\x18\x70\x3A"
		"\xAA\x7B\xFF\x3F\x09\xF5\x16\x9C\xAF\x5D\xBA\x66\x02\xA0\x5A\x4D"
		"\x5C\xFF\x55\x53\xD4\x2E\x82\xE4\x05\x16\xD6\xDC\x15\x7B\x8D\xAE"
		"\xAE\x61\xD3\xFE\xA4\x56\xD9\x64\xCB\x2F\x7F\x9A\x63\xBB\xBD\xB5"
	},
	{ // Long Test 6a 1 iter 64 outputbytes Len65pw Len65sa
		1,
		"passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U",
		"saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk",
		64,
		"\x28\xB8\xA9\xF6\x44\xD6\x80\x06\x12\x19\x7B\xB7\x4D\xF4\x60\x27"
		"\x2E\x22\x76\xDE\x8C\xC0\x7A\xC4\x89\x7A\xC2\x4D\xBC\x6E\xB7\x74"
		"\x99\xFC\xAF\x97\x41\x52\x44\xD9\xA2\x9D\xA8\x3F\xC3\x47\xD0\x9A"
		"\x5D\xBC\xFD\x6B\xD6\x3F\xF6\xE4\x10\x80\x3D\xCA\x8A\x90\x0A\xB6"
	},
	{ // Long Test 6b 100000 iter 64 outputbytes Len65pw Len65sa
		100000,
		"passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U",
		"saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk",
		64,
		"\x05\x6B\xC9\x07\x2A\x35\x6B\x7D\x4D\xA6\x0D\xD6\x6F\x59\x68\xC2"
		"\xCA\xA3\x75\xC0\x22\x0E\xDA\x6B\x47\xEF\x8E\x8D\x10\x5E\xD6\x8B"
		"\x44\x18\x5F\xE9\x00\x3F\xBB\xA4\x9E\x2C\x84\x24\x0C\x9E\x8F\xD3"
		"\xF5\xB2\xF4\xF6\x51\x2F\xD9\x36\x45\x02\x53\xDB\x37\xD1\x00\x28"
	},
	{ // Long Test 7a 1 iter 64 outputbytes Len127pw Len127sa
		1,
		"passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi0",
		"saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy",
		64,
		"\x16\x22\x6C\x85\xE4\xF8\xD6\x04\x57\x30\x08\xBF\xE6\x1C\x10\xB6"
		"\x94\x7B\x53\x99\x04\x50\x61\x2D\xD4\xA3\x07\x7F\x7D\xEE\x21\x16"
		"\x22\x9E\x68\xEF\xD1\xDF\x6D\x73\xBD\x3C\x6D\x07\x56\x77\x90\xEE"
		"\xA1\xE8\xB2\xAE\x9A\x1B\x04\x6B\xE5\x93\x84\x7D\x94\x41\xA1\xB7"
	},
	{ // Long Test 7b 100000 iter 64 outputbytes Len127pw Len127sa
		100000,
		"passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi0",
		"saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy",
		64,
		"\x70\xCF\x39\xF1\x4C\x4C\xAF\x3C\x81\xFA\x28\x8F\xB4\x6C\x1D\xB5"
		"\x2D\x19\xF7\x27\x22\xF7\xBC\x84\xF0\x40\x67\x6D\x33\x71\xC8\x9C"
		"\x11\xC5\x0F\x69\xBC\xFB\xC3\xAC\xB0\xAB\x9E\x92\xE4\xEF\x62\x27"
		"\x27\xA9\x16\x21\x95\x54\xB2\xFA\x12\x1B\xED\xDA\x97\xFF\x33\x32"
	},
	{ // Long Test 8a 1 iter 64 outputbytes Len128pw Len128sa
		1,
		"passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04",
		"saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6",
		64,
		"\x88\x0C\x58\xC3\x16\xD3\xA5\xB9\xF0\x59\x77\xAB\x9C\x60\xC1\x0A"
		"\xBE\xEB\xFA\xD5\xCE\x89\xCA\xE6\x29\x05\xC1\xC4\xF8\x0A\x0A\x09"
		"\x8D\x82\xF9\x53\x21\xA6\x22\x0F\x8A\xEC\xCF\xB4\x5C\xE6\x10\x71"
		"\x40\x89\x9E\x8D\x65\x53\x06\xAE\x63\x96\x55\x3E\x28\x51\x37\x6C"
	},
	{ // Long Test 8b 100000 iter 64 outputbytes Len128pw Len128sa
		100000,
		"passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04",
		"saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6",
		64,
		"\x26\x68\xB7\x1B\x3C\xA5\x61\x36\xB5\xE8\x7F\x30\xE0\x98\xF6\xB4"
		"\x37\x1C\xB5\xED\x95\x53\x7C\x7A\x07\x3D\xAC\x30\xA2\xD5\xBE\x52"
		"\x75\x6A\xDF\x5B\xB2\xF4\x32\x0C\xB1\x1C\x4E\x16\xB2\x49\x65\xA9"
		"\xC7\x90\xDE\xF0\xCB\xC6\x29\x06\x92\x0B\x4F\x2E\xB8\x4D\x1D\x4A"
	},
#ifndef SMALL_CODE // in a small implementation, salt more than 128 bytes is not supported
	{ // Long Test 9a 1 iter 64 outputbytes Len129pw Len129sa
		1,
		"passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04U",
		"saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6P",
		64,
		"\x93\xB9\xBA\x82\x83\xCC\x17\xD5\x0E\xF3\xB4\x48\x20\x82\x8A\x25"
		"\x8A\x99\x6D\xE2\x58\x22\x5D\x24\xFB\x59\x99\x0A\x6D\x0D\xE8\x2D"
		"\xFB\x3F\xE2\xAC\x20\x19\x52\x10\x0E\x4C\xC8\xF0\x6D\x88\x3A\x91"
		"\x31\x41\x9C\x0F\x6F\x5A\x6E\xCB\x8E\xC8\x21\x54\x5F\x14\xAD\xF1"
	},
	{ // Long Test 9b 100000 iter 64 outputbytes Len129pw Len129sa
		100000,
		"passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04U",
		"saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6P",
		64,
		"\x25\x75\xB4\x85\xAF\xDF\x37\xC2\x60\xB8\xF3\x38\x6D\x33\xA6\x0E"
		"\xD9\x29\x99\x3C\x9D\x48\xAC\x51\x6E\xC6\x6B\x87\xE0\x6B\xE5\x4A"
		"\xDE\x7E\x7C\x8C\xB3\x41\x7C\x81\x60\x3B\x08\x0A\x8E\xEF\xC5\x60"
		"\x72\x81\x11\x29\x73\x7C\xED\x96\x23\x6B\x93\x64\xE2\x2C\xE3\xA5"
	},
	{ // Long Test 10a 1 iter 64 outputbytes Len1025pw Len1025sa
		1,
		"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",
		64,
		"\x38\x4B\xCD\x69\x14\x40\x7E\x40\xC2\x95\xD1\x03\x7C\xF4\xF9\x90"
		"\xE8\xF0\xE7\x20\xAF\x43\xCB\x70\x66\x83\x17\x70\x16\xD3\x6D\x1A"
		"\x14\xB3\xA7\xCF\x22\xB5\xDF\x8D\x5D\x7D\x44\xD6\x96\x10\xB6\x42"
		"\x51\xAD\xE2\xE7\xAB\x54\xA3\x81\x3A\x89\x93\x55\x92\xE3\x91\xBF"
	},
	{ // Long Test 10b 100000 iter 64 outputbytes Len1025pw Len1025sa
		100000,
		"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",
		64,
		"\xB8\x67\x4F\x6C\x0C\xC9\xF8\xCF\x1F\x18\x74\x53\x4F\xD5\xAF\x01"
		"\xFC\x15\x04\xD7\x6C\x2B\xC2\xAA\x0A\x75\xFE\x4D\xD5\xDF\xD1\xDA"
		"\xF6\x0E\xA7\xC8\x5F\x12\x2B\xCE\xEB\x87\x72\x65\x9D\x60\x12\x31"
		"\x60\x77\x26\x99\x8E\xAC\x3F\x6A\xAB\x72\xEF\xF7\xBA\x34\x9F\x7F"
	}
#endif
};

int test_pkcs5()
{
	const char   *pass, *salt;
	unsigned char dk[144];
	int           i, dklen;

	// test PKDBF2
	for (i = 0; i < _countof(pkcs5_vectors); i++)
	{
		pass  = pkcs5_vectors[i].password;
		salt  = pkcs5_vectors[i].salt;
		dklen = pkcs5_vectors[i].dklen;

		sha512_pkcs5_2(pkcs5_vectors[i].i_count, pass, strlen(pass), salt, strlen(salt), dk, dklen);
		if (memcmp(dk, pkcs5_vectors[i].key, dklen) != 0) return 0;
	}

	// all tests passed
	return 1;
}