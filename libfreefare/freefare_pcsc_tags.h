#ifndef __FREEFARE_PCSC_TAGS_H__
#define __FREEFARE_PCSC_TAGS_H__

struct pcsc_atr_info { 

	enum freefare_tag_type type;
	unsigned int len;
	char* tag;
	char* mask;

};

struct pcsc_atr_info pcsc_supported_atrs[] = {
	{ MIFARE_DESFIRE     ,  6, "\x3b\x04\x41\x11\x77\x81", NULL},
	{ MIFARE_DESFIRE     ,  6, "\x3b\x81\x80\x01\x80\x80", NULL },
	{ MIFARE_CLASSIC_1K  , 20, "\x3b\x8f\x80\x01\x80\x4f\x0c\xa0\x00\x00\x03\x06\x03\x00\x01\x00\x00\x00\x00\x6a",
	                    /*"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\x00"*/ NULL },
	{ MIFARE_CLASSIC_4K  , 20, "\x3b\x8f\x80\x01\x80\x4f\x0c\xa0\x00\x00\x03\x06\x03\x00\x02\x00\x00\x00\x00\x69", 
	                    /*"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\x00"*/ NULL },
	{ MIFARE_ULTRALIGHT  , 20, "\x3b\x8f\x80\x01\x80\x4f\x0c\xa0\x00\x00\x03\x06\x03\x00\x03\x00\x00\x00\x00\x68", 
	                    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\x00" },
	{ MIFARE_ULTRALIGHT  , 20, "\x3b\x8f\x80\x01\x80\x4f\x0c\xa0\x00\x00\x03\x06\x03\x00\x03\x00\x00\x00\x00\x68",
	                    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x00" },
	{ MIFARE_DESFIRE     , 0 , NULL, NULL}
};

#ifndef USE_LIBNFC
// From https://github.com/nfc-tools/libnfc/blob/master/include/nfc/nfc-types.h#L295
// Only if libnfc cannot provide these symbols
typedef enum {
  NMT_ISO14443A = 1,
  NMT_JEWEL,
  NMT_ISO14443B,
  NMT_ISO14443BI, // pre-ISO14443B aka ISO/IEC 14443 B' or Type B'
  NMT_ISO14443B2SR, // ISO14443-2B ST SRx
  NMT_ISO14443B2CT, // ISO14443-2B ASK CTx
  NMT_FELICA,
  NMT_DEP,
} nfc_modulation_type;
#endif

#endif /* __FREEFARE_PCSC_TAGS_H__ */

