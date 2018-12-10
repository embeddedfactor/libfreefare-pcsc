/*-
 * Copyright (C) 2010, Romain Tartiere, Romuald Conty.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "config.h"

#ifdef USE_LIBNFC
#include <nfc/nfc.h>
#include <freefare.h>
#endif
#ifdef USE_PCSC
#include "freefare_pcsc.h"
#endif

#include <reader.h>

#include "freefare_internal.h"

#ifdef USE_PCSC
#include "freefare_pcsc_tags.h"
#endif

#define MAX_CANDIDATES 16

#define NXP_MANUFACTURER_CODE 0x04

struct supported_tag supported_tags[] = {
    { FELICA,              "FeliCA",                       NMT_FELICA,    0x00, 0, 0, { 0x00 }, NULL },
    { MIFARE_CLASSIC_1K,   "Mifare Classic 1k",            NMT_ISO14443A, 0x08, 0, 0, { 0x00 }, NULL },
    { MIFARE_CLASSIC_1K,   "Mifare Classic 1k (Emulated)", NMT_ISO14443A, 0x28, 0, 0, { 0x00 }, NULL },
    { MIFARE_CLASSIC_1K,   "Mifare Classic 1k (Emulated)", NMT_ISO14443A, 0x68, 0, 0, { 0x00 }, NULL },
    { MIFARE_CLASSIC_1K,   "Infineon Mifare Classic 1k",   NMT_ISO14443A, 0x88, 0, 0, { 0x00 }, NULL },
    { MIFARE_CLASSIC_4K,   "Mifare Classic 4k",            NMT_ISO14443A, 0x18, 0, 0, { 0x00 }, NULL },
    { MIFARE_CLASSIC_4K,   "Mifare Classic 4k (Emulated)", NMT_ISO14443A, 0x38, 0, 0, { 0x00 }, NULL },
    { MIFARE_DESFIRE,      "Mifare DESFire",               NMT_ISO14443A, 0x20, 5, 4, { 0x75, 0x77, 0x81, 0x02 /*, 0xXX */ }, NULL},
    { MIFARE_DESFIRE,      "Cyanogenmod card emulation",   NMT_ISO14443A, 0x60, 4, 3, { 0x78, 0x33, 0x88 /*, 0xXX */ }, NULL},
    { MIFARE_DESFIRE,      "Android HCE",                  NMT_ISO14443A, 0x60, 4, 3, { 0x78, 0x80, 0x70 /*, 0xXX */ }, NULL},
#if defined(is_mifare_ultralightc_on_reader)
    { MIFARE_ULTRALIGHT_C, "Mifare UltraLightC",           NMT_ISO14443A, 0x00, 0, 0, { 0x00 }, is_mifare_ultralightc_on_reader },
#else
    { MIFARE_ULTRALIGHT_C, "Mifare UltraLightC",           NMT_ISO14443A, 0x00, 0, 0, { 0x00 }, NULL},
#endif
    { MIFARE_ULTRALIGHT,   "Mifare UltraLight",            NMT_ISO14443A, 0x00, 0, 0, { 0x00 }, NULL },
};

#ifdef USE_LIBNFC
/*
 * Automagically allocate a FreefareTag given a device and target info.
 */
FreefareTag
freefare_tag_new (nfc_device *device, nfc_target target)
{
    bool found = false;
    struct supported_tag *tag_info;
    FreefareTag tag;
    size_t i = 0;

    /* Ensure the target is supported */
    for (i = 0; i < sizeof (supported_tags) / sizeof (struct supported_tag); i++) {
	if (target.nm.nmt != supported_tags[i].modulation_type)
	    continue;

	if (target.nm.nmt == NMT_FELICA) {
	    tag_info = &(supported_tags[i]);
	    found = true;
	    break;
	}
	if ((target.nm.nmt == NMT_ISO14443A) && ((target.nti.nai.szUidLen == 4) || (target.nti.nai.abtUid[0] == NXP_MANUFACTURER_CODE)) &&
	    (target.nti.nai.btSak == supported_tags[i].SAK) &&
	    (!supported_tags[i].ATS_min_length || ((target.nti.nai.szAtsLen >= supported_tags[i].ATS_min_length) &&
						   (0 == memcmp (target.nti.nai.abtAts, supported_tags[i].ATS, supported_tags[i].ATS_compare_length)))) &&
	    ((supported_tags[i].check_tag_on_reader == NULL) ||
	     supported_tags[i].check_tag_on_reader(device, target.nti.nai))) {

	    tag_info = &(supported_tags[i]);
	    found = true;
	    break;
	}
    }

    if (!found)
	return NULL;

    /* Allocate memory for the found MIFARE target */
    switch (tag_info->type) {
    case FELICA:
	tag = felica_tag_new ();
	break;
    case MIFARE_CLASSIC_1K:
    case MIFARE_CLASSIC_4K:
	tag = mifare_classic_tag_new ();
	break;
    case MIFARE_DESFIRE:
	tag = mifare_desfire_tag_new ();
	break;
    case MIFARE_ULTRALIGHT:
    case MIFARE_ULTRALIGHT_C:
	tag = mifare_ultralight_tag_new ();
	break;
    }

    if (!tag)
	    return NULL;

    /*
     * Initialize common fields
     * (Target specific fields are initialized in mifare_*_tag_new())
     */
    tag->device = device;
    tag->info = target;
    tag->active = 0;
    tag->tag_info = tag_info;
#ifdef USE_PCSC
    tag->szReader = NULL;
#endif

    return tag;
}
#endif
#ifdef USE_PCSC
FreefareTag
freefare_tag_new_pcsc (struct pcsc_context *context, const char *reader)
{
    struct supported_tag *tag_info = NULL;
    enum freefare_tag_type tagtype;
    bool found = false;
    uint8_t buf[] = { 0xFF, 0xCA, 0x00, 0x00, 0x00 };
    uint8_t ret[12];
    unsigned char pbAttr[MAX_ATR_SIZE];
    unsigned int k;
    char crc = 0x00;
    size_t size;
    FreefareTag tag = NULL;
    LONG err;
    DWORD atrlen = sizeof(pbAttr);
    DWORD dwActiveProtocol;
    DWORD retlen;
    SCARDHANDLE hCard;
    SCARD_IO_REQUEST sendpci;
    /* SCARD_IO_REQUEST ioreq; // TODO: Unused?? */

    err = SCardConnect(context->context, reader, SCARD_SHARE_SHARED,
			SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
    if(err)
	return NULL;

    switch (dwActiveProtocol)
    {
	case SCARD_PROTOCOL_T0: sendpci = *SCARD_PCI_T0;
	     break;
	case SCARD_PROTOCOL_T1: sendpci = *SCARD_PCI_T1;
	     break;
    }

    /* get and card uid */
    retlen = sizeof(ret);
    err = SCardTransmit(hCard, &sendpci, buf, sizeof(buf), NULL /*&ioreq*/, ret, &retlen);
    if (err)
    {
	return NULL;
    }

    err = SCardGetAttrib ( hCard , SCARD_ATTR_ATR_STRING, (unsigned char *) &pbAttr, &atrlen );
    if (err)
    {
	return NULL;
    }

    found = false;
    for (k = 0; pcsc_supported_atrs[k].len != 0; k++){
	if (atrlen != pcsc_supported_atrs[k].len) {
	    continue;
	}
	if ( pcsc_supported_atrs[k].mask == NULL ){
	    /* no bitmask here */
	    if ( ! memcmp(pcsc_supported_atrs[k].tag ,pbAttr ,atrlen) ) {
		tagtype = pcsc_supported_atrs[k].type;
		found = true;
		break;
	    }
	} else {
	    /* bitmask case */
	    unsigned int c = 0;
	    for (c = 0; c < pcsc_supported_atrs[k].len; c++){
		if((pcsc_supported_atrs[k].tag[c] & pcsc_supported_atrs[k].mask[c]) != (pbAttr[c] & pcsc_supported_atrs[k].mask[c])){
		    break;
		}
	    }
	    if (c == pcsc_supported_atrs[k].len) {
		tagtype = pcsc_supported_atrs[k].type;
		found = true;
		break;
	    }
	}
    }
    if (!found) {
	return NULL;
    }

    found = false;
    for (size = 0; size < sizeof (supported_tags) / sizeof (struct supported_tag); size++) {
	if(supported_tags[size].type == tagtype) {
	    tag_info = &(supported_tags[size]);
	    found = true;
	    break;
	}
    }

    if(!found)
	return NULL;

    for (k = 1 /*! 1. Byte wird ignoriert*/ ; k < atrlen; k++ )
    {
	crc ^= pbAttr[k];
    }
    if (crc)
    	return NULL;

    /* Allocate memory for the found MIFARE target */
    switch (tag_info->type) {
    case FELICA:
	return NULL;
	/* Felica tags not yet supported with PCSC */
	/* tag = felica_tag_new (); */
	break;
    case MIFARE_CLASSIC_1K:
    case MIFARE_CLASSIC_4K:
	return NULL;
	/* classic tags not yet supported with PCSC */
	/* tag = mifare_classic_tag_new (); */
	break;
    case MIFARE_DESFIRE:
	tag = mifare_desfire_tag_new ();
        tag->info.nm.nmt = NMT_ISO14443A;

	break;
    case MIFARE_ULTRALIGHT:
    case MIFARE_ULTRALIGHT_C:
	return NULL;
	/* ultralight tags not yet supported with PCSC */
	/* tag = mifare_ultralight_tag_new (); */
	break;
    }

    if (!tag)
	return NULL;

    /*
     * Initialize common fields
     * (Target specific fields are initialized in mifare_*_tag_new())
     */
    memcpy(tag->info.nti.nai.abtUid, ret, retlen - 2);
    tag->info.nti.nai.szUidLen = retlen - 2;
#if USE_LIBNFC
    tag->device = NULL;
#endif
    tag->hContext = context->context;
    tag->hCard = hCard;
    tag->active = 0;
    tag->tag_info = tag_info;
    FILL_SZREADER(tag, reader);

    tag->lastPCSCerror = SCardDisconnect(tag->hCard, SCARD_LEAVE_CARD);

    return tag;
}
#endif
/*
 * MIFARE card common functions
 *
 * The following functions send NFC commands to the initiator to prepare
 * communication with a MIFARE card, and perform required cleannups after using
 * the targets.
 */
#ifdef USE_LIBNFC
/*
 * Get a list of the MIFARE targets near to the provided NFC initiator.
 *
 * The list has to be freed using the freefare_free_tags() function.
 */
FreefareTag *
freefare_get_tags (nfc_device *device)
{
    FreefareTag *tags = NULL;
    int tag_count = 0;
    nfc_initiator_init(device);

    // Drop the field for a while
    nfc_device_set_property_bool(device,NP_ACTIVATE_FIELD,false);

    // Configure the CRC and Parity settings
    nfc_device_set_property_bool(device,NP_HANDLE_CRC,true);
    nfc_device_set_property_bool(device,NP_HANDLE_PARITY,true);
    nfc_device_set_property_bool(device,NP_AUTO_ISO14443_4,true);

    // Enable field so more power consuming cards can power themselves up
    nfc_device_set_property_bool(device,NP_ACTIVATE_FIELD,true);

    // Poll for a ISO14443A (MIFARE) tag
    nfc_target candidates[MAX_CANDIDATES];
    int candidates_count;
    nfc_modulation modulation = {
	.nmt = NMT_ISO14443A,
	.nbr = NBR_106
    };
    if ((candidates_count = nfc_initiator_list_passive_targets(device, modulation, candidates, MAX_CANDIDATES)) < 0)
	return NULL;

    tags = malloc(sizeof (void *));
    if(!tags) return NULL;
    tags[0] = NULL;

    for (int c = 0; c < candidates_count; c++) {
	FreefareTag t;
	if ((t = freefare_tag_new(device, candidates[c]))) {
	    /* (Re)Allocate memory for the found MIFARE targets array */
	    FreefareTag *p = realloc (tags, (tag_count + 2) * sizeof (FreefareTag));
	    if (p)
		tags = p;
	    else
		return tags; // FAIL! Return what has been found so far.
	    tags[tag_count++] = t;
	    tags[tag_count] = NULL;
	}
    }

    // Poll for a FELICA tag
    modulation.nmt = NMT_FELICA;
    modulation.nbr = NBR_424; // FIXME NBR_212 should also be supported
    if ((candidates_count = nfc_initiator_list_passive_targets(device, modulation, candidates, MAX_CANDIDATES)) < 0)
	return NULL;

    for (int c = 0; c < candidates_count; c++) {
	FreefareTag t;
	if ((t = freefare_tag_new(device, candidates[c]))) {
	    /* (Re)Allocate memory for the found FELICA targets array */
	    FreefareTag *p = realloc (tags, (tag_count + 2) * sizeof (FreefareTag));
	    if (p)
		tags = p;
	    else
		return tags; // FAIL! Return what has been found so far.
	    tags[tag_count++] = t;
	    tags[tag_count] = NULL;
	}
    }

    return tags;
}
#endif
#ifdef USE_PCSC
/*
 * Get a list of the MIFARE targets near to the provided NFC initiator.
 * (Usally its just one tag, because pcsc can not detect more)
 * phContext must be established with SCardEstablishContext before
 * calling this function.
 * mszReader is the Name of the SmartCard Reader to use
 * The list has to be freed using the freefare_free_tags() function.
 */
FreefareTag *
freefare_get_tags_pcsc (struct pcsc_context *context, const char *reader)
{
    FreefareTag *tags = NULL;

    tags = (FreefareTag *)malloc(2*sizeof (FreefareTag));
    if(!tags)
    {
	return NULL;
    }
    tags[0] = freefare_tag_new_pcsc(context, reader);
    tags[1] = NULL;
    if(tags[0] == NULL)
    	return NULL;

    return tags;
}
#endif
/*
 * Returns the type of the provided tag.
 */
enum freefare_tag_type
freefare_get_tag_type (FreefareTag tag)
{
    return tag->tag_info->type;
}

/*
 * Returns the friendly name of the provided tag.
 */
const char *
freefare_get_tag_friendly_name (FreefareTag tag)
{
    return tag->tag_info->friendly_name;
}

/*
 * Returns the UID of the provided tag.
 */
char *
freefare_get_tag_uid (FreefareTag tag)
{
    size_t i;
    char *res = NULL;
    switch (tag->info.nm.nmt) {
        case NMT_FELICA:
            if ((res = (char *)malloc (17))) {
                for (i = 0; i < 8; i++)
                    snprintf (res + 2*i, 3, "%02x", tag->info.nti.nfi.abtId[i]);
            } break;
        case NMT_ISO14443A:
            if ((res = (char *)malloc (2 * tag->info.nti.nai.szUidLen + 1))) {
                for (i = 0; i < tag->info.nti.nai.szUidLen; i++)
                    snprintf (res + 2*i, 3, "%02x", tag->info.nti.nai.abtUid[i]);
            } break;
        case NMT_DEP:
        case NMT_ISO14443B2CT:
        case NMT_ISO14443B2SR:
        case NMT_ISO14443B:
        case NMT_ISO14443BI:
        case NMT_JEWEL:
            res = strdup ("UNKNOWN");
    }
    return res;
}

#ifdef USE_LIBNFC
/*
 * Returns true if last selected tag is still present.
 */
bool freefare_selected_tag_is_present(nfc_device *device)
{
    return (nfc_initiator_target_is_present(device, NULL) == NFC_SUCCESS);
}
#endif

/*
 * Free the provided tag.
 */
void
freefare_free_tag (FreefareTag tag)
{
#ifdef USE_PCSC
    if(tag->szReader) {
	    FREE_SZREADER(tag->szReader);
    }
#endif
    if (tag) {
        switch (tag->tag_info->type) {
        case FELICA:
#ifdef USE_LIBNFC
            felica_tag_free (tag);
#endif
            break;
        case MIFARE_CLASSIC_1K:
        case MIFARE_CLASSIC_4K:
            mifare_classic_tag_free (tag);
            break;
        case MIFARE_DESFIRE:
            mifare_desfire_tag_free (tag);
            break;
        case MIFARE_ULTRALIGHT:
        case MIFARE_ULTRALIGHT_C:
            mifare_ultralight_tag_free (tag);
            break;
        }
    }
}

const char *
freefare_strerror (FreefareTag tag)
{
    const char *p = "Unknown error";
#if defined(USE_LIBNFC) && defined(USE_PCSC)
    if(tag->device != NULL) // we use libnfc
#endif
#ifdef USE_LIBNFC
    {
        if (nfc_device_get_last_error (tag->device) < 0) {
            p = nfc_strerror (tag->device);
        } else {
            if (tag->tag_info->type == MIFARE_DESFIRE) {
                if (MIFARE_DESFIRE (tag)->last_pcd_error) {
                    p = mifare_desfire_error_lookup (MIFARE_DESFIRE (tag)->last_pcd_error);
                } else if (MIFARE_DESFIRE (tag)->last_picc_error) {
                    p = mifare_desfire_error_lookup (MIFARE_DESFIRE (tag)->last_picc_error);
                }
            }
        }
    }
#endif
#if defined(USE_LIBNFC) && defined(USE_PCSC)
    else // we use the pcsc protocol
#endif
#ifdef USE_PCSC
    {
        if (tag->lastPCSCerror != 0){
#ifdef _WIN32
              char    wszMsgBuff[512];  // Buffer for text.
              size_t  dwChars;  // Number of chars returned.
              // Try to get the message from the system errors.
              dwChars = FormatMessageA( FORMAT_MESSAGE_FROM_SYSTEM |
                             FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL,
                             tag->lastPCSCerror,
                             0,
                             wszMsgBuff,
                             512,
                             NULL );
            return wszMsgBuff;
#else
            p = (const char*) pcsc_stringify_error(tag->lastPCSCerror);
            return p;
#endif
        } else {
            if (tag->tag_info->type == MIFARE_DESFIRE) {
                if (MIFARE_DESFIRE (tag)->last_pcd_error) {
                    p = mifare_desfire_error_lookup (MIFARE_DESFIRE (tag)->last_pcd_error);
                } else if (MIFARE_DESFIRE (tag)->last_picc_error) {
                    p = mifare_desfire_error_lookup (MIFARE_DESFIRE (tag)->last_picc_error);
                }
            }
        }
    }
#endif
    return p;
}

unsigned int freefare_internal_error(FreefareTag tag) {
#if defined(USE_LIBNFC) && defined(USE_PCSC)
    if(tag->device != NULL) // we use libnfc
#endif
#ifdef USE_LIBNFC
    {
        if (nfc_device_get_last_error (tag->device) < 0) {
          return nfc_device_get_last_error(tag->device);
        } else {
            if (tag->tag_info->type == MIFARE_DESFIRE) {
                if (MIFARE_DESFIRE (tag)->last_pcd_error) {
                    return (MIFARE_DESFIRE (tag)->last_pcd_error);
                } else if (MIFARE_DESFIRE (tag)->last_picc_error) {
                    return (MIFARE_DESFIRE (tag)->last_picc_error);
                }
            }
        }
    }
#endif
#if defined(USE_LIBNFC) && defined(USE_PCSC)
    else // we use the pcsc protocol
#endif
#ifdef USE_PCSC
    {
        if (tag->lastPCSCerror != 0){
            return (unsigned int)tag->lastPCSCerror;
        } else {
            if (tag->tag_info->type == MIFARE_DESFIRE) {
                if (MIFARE_DESFIRE (tag)->last_pcd_error) {
                    return (unsigned int)(MIFARE_DESFIRE (tag)->last_pcd_error);
                } else if (MIFARE_DESFIRE (tag)->last_picc_error) {
                    return (unsigned int)(MIFARE_DESFIRE (tag)->last_picc_error);
                }
            }
        }
    }
#endif
    return 0;

}

void freefare_clear_internal_error(FreefareTag tag) {
    (MIFARE_DESFIRE (tag)->last_pcd_error) = 0;
    (MIFARE_DESFIRE (tag)->last_picc_error) = 0;
#ifdef USE_PCSC
      tag->lastPCSCerror = 0;
#endif
}

int
freefare_strerror_r (FreefareTag tag, char *buffer, size_t len)
{
    return (snprintf (buffer, len, "%s", freefare_strerror (tag)) < 0) ? -1 : 0;
}

void
freefare_perror (FreefareTag tag, const char *string)
{
    fprintf (stderr, "%s: %s\n", string, freefare_strerror (tag));
}

/*
 * Free the provided tag list.
 */
void
freefare_free_tags (FreefareTag *tags)
{
  int i;
    if (tags) {
	for (i=0; tags[i]; i++) {
	    freefare_free_tag(tags[i]);
      tags[i] = NULL;
	}
  // last allocated mem for tag, with NULL in it
  free(tags[i]);
	free (tags);
  tags = NULL;
    }
}

/*
 * create context for pcsc readers
 */
#ifdef USE_PCSC
void
pcsc_init(struct pcsc_context** context)
{
	LONG err;
	struct pcsc_context *con =  (struct pcsc_context *)malloc(sizeof(struct pcsc_context));
	err = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &con->context);
	if (err < 0)
	{
		*context = NULL;
		return;
	}
	*context = con;
}

/*
 * destroy context for pcsc readers
 */
void
pcsc_exit(struct pcsc_context* context)
{
	if (context->readers)
    #ifndef __APPLE__
		SCardFreeMemory(context->context, context->readers);
    #endif
	SCardReleaseContext(context->context);
}

/*
 * list pcsc devices
 */

LONG
pcsc_list_devices(struct pcsc_context* context, LPSTR *string)
{
    LONG err;
    LPSTR str = NULL;
    DWORD size;
    static char empty[] = "\0";

    err = SCardListReaders(context->context, NULL, NULL, &size);
    str = (char *)malloc(sizeof(char) * size);
    if (!str)
    {
    	context->readers = NULL;
	    *string = empty;
    	return SCARD_E_NO_MEMORY;
    }
    err = SCardListReaders(context->context, NULL, str, &size);
    if (err != SCARD_S_SUCCESS)
    {
      context->readers = NULL;
      *string = empty;
    }
    else
    {
      *string = str;
      context->readers = str;
    }
    return err;
}
#endif
/*
 * Low-level API
 */

void *
memdup (const void *p, const size_t n)
{
    void *res;
    if ((res = malloc (n))) {
	memcpy (res, p, n);
    }
    return res;
}
