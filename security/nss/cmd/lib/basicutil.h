/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#ifndef _BASIC_UTILS_H_
#define _BASIC_UTILS_H_

#include "seccomon.h"
#include "secitem.h"
#include "secoid.h"
#include "secoidt.h"
#include "secport.h"
#include "key.h"
#include "prerror.h"
#include "base64.h"
#include "key.h"
#include "secpkcs7.h"
#include "secasn1.h"
#include "secder.h"
#include <stdio.h>

#ifdef SECUTIL_NEW
typedef int (*SECU_PPFunc)(PRFileDesc *out, SECItem *item, 
                           char *msg, int level);
#else
typedef int (*SECU_PPFunc)(FILE *out, SECItem *item, char *msg, int level);
#endif

/* print out an error message */
extern void SECU_PrintError(char *progName, char *msg, ...);

/* print out a system error message */
extern void SECU_PrintSystemError(char *progName, char *msg, ...);

/* print a formatted error message */
extern void SECU_PrintErrMsg(FILE *out, int level, char *progName, char *msg, ...);

/* Read the contents of a file into a SECItem */
extern SECStatus SECU_FileToItem(SECItem *dst, PRFileDesc *src);
extern SECStatus SECU_TextFileToItem(SECItem *dst, PRFileDesc *src);

/* Indent based on "level" */
extern void SECU_Indent(FILE *out, int level);

/* Print a newline to out */
extern void SECU_Newline(FILE *out);

/* Print integer value and hex */
extern void SECU_PrintInteger(FILE *out, SECItem *i, char *m, int level);

/* Print SECItem as hex */
extern void SECU_PrintAsHex(FILE *out, SECItem *i, const char *m, int level);

/* dump a buffer in hex and ASCII */
extern void SECU_PrintBuf(FILE *out, const char *msg, const void *vp, int len);

/* Dump contents of an RSA public key */
extern void SECU_PrintRSAPublicKey(FILE *out, SECKEYPublicKey *pk, char *m, int level);

/* Dump contents of a DSA public key */
extern void SECU_PrintDSAPublicKey(FILE *out, SECKEYPublicKey *pk, char *m, int level);

#ifdef HAVE_EPV_TEMPLATE
/* Dump contents of private key */
extern int SECU_PrintPrivateKey(FILE *out, SECItem *der, char *m, int level);
#endif

/* Print the MD5 and SHA1 fingerprints of a cert */
extern int SECU_PrintFingerprints(FILE *out, SECItem *derCert, char *m,
                                  int level);

/* Pretty-print any PKCS7 thing */
extern int SECU_PrintPKCS7ContentInfo(FILE *out, SECItem *der, char *m, 
				      int level);

/* Init PKCS11 stuff */
extern SECStatus SECU_PKCS11Init(PRBool readOnly);

/* Dump contents of signed data */
extern int SECU_PrintSignedData(FILE *out, SECItem *der, const char *m, 
                                int level, SECU_PPFunc inner);

/* Print cert data and its trust flags */
extern SECStatus SEC_PrintCertificateAndTrust(CERTCertificate *cert,
                                              const char *label,
                                              CERTCertTrust *trust);

extern int SECU_PrintCrl(FILE *out, SECItem *der, char *m, int level);

extern void
SECU_PrintCRLInfo(FILE *out, CERTCrl *crl, char *m, int level);

extern void SECU_PrintString(FILE *out, SECItem *si, char *m, int level);
extern void SECU_PrintAny(FILE *out, SECItem *i, char *m, int level);

extern void SECU_PrintPolicy(FILE *out, SECItem *value, char *msg, int level);
extern void SECU_PrintPrivKeyUsagePeriodExtension(FILE *out, SECItem *value,
                                 char *msg, int level);

extern void SECU_PrintExtensions(FILE *out, CERTCertExtension **extensions,
				 char *msg, int level);

extern void SECU_PrintNameQuotesOptional(FILE *out, CERTName *name, 
					 const char *msg, int level, 
					 PRBool quotes);
extern void SECU_PrintName(FILE *out, CERTName *name, const char *msg,
                           int level);
extern void SECU_PrintRDN(FILE *out, CERTRDN *rdn, const char *msg, int level);

#ifdef SECU_GetPassword
/* Convert a High public Key to a Low public Key */
extern SECKEYLowPublicKey *SECU_ConvHighToLow(SECKEYPublicKey *pubHighKey);
#endif

extern char *SECU_GetModulePassword(PK11SlotInfo *slot, PRBool retry, void *arg);

extern SECStatus DER_PrettyPrint(FILE *out, SECItem *it, PRBool raw);

extern char *SECU_SECModDBName(void);

extern void SECU_PrintPRandOSError(char *progName);

extern SECStatus SECU_RegisterDynamicOids(void);

/* Identifies hash algorithm tag by its string representation. */
extern SECOidTag SECU_StringToSignatureAlgTag(const char *alg);

/* Caller ensures that dst is at least item->len*2+1 bytes long */
void
SECU_SECItemToHex(const SECItem * item, char * dst);

/* Requires 0x prefix. Case-insensitive. Will do in-place replacement if
 * successful */
SECStatus
SECU_SECItemHexStringToBinary(SECItem* srcdest);

/*
 *
 *  Utilities for parsing security tools command lines 
 *
 */

/*  A single command flag  */
typedef struct {
    char flag;
    PRBool needsArg;
    char *arg;
    PRBool activated;
    char *longform;
} secuCommandFlag;

/*  A full array of command/option flags  */
typedef struct
{
    int numCommands;
    int numOptions;

    secuCommandFlag *commands;
    secuCommandFlag *options;
} secuCommand;

/*  fill the "arg" and "activated" fields for each flag  */
SECStatus 
SECU_ParseCommandLine(int argc, char **argv, char *progName,
		      const secuCommand *cmd);
char *
SECU_GetOptionArg(const secuCommand *cmd, int optionNum);

/*
 *
 *  Error messaging
 *
 */

void printflags(char *trusts, unsigned int flags);

#if !defined(XP_UNIX) && !defined(XP_OS2)
extern int ffs(unsigned int i);
#endif

/* Finds certificate by searching it in the DB or by examinig file
 * in the local directory. */
CERTCertificate*
SECU_FindCertByNicknameOrFilename(CERTCertDBHandle *handle,
                                  char *name, PRBool ascii,
                                  void *pwarg);
#include "secerr.h"

extern const char *hex;
extern const char printable[];

#endif /* _BASIC_UTILS_H_ */
