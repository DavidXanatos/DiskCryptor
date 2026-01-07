/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/


#ifndef _XML_H_
#define _XML_H_

#ifdef __cplusplus
extern "C" {
#endif

char *XmlNextNode (char *xmlNode);
char *XmlFindElement (char *xmlNode, char *nodeName);
char *XmlGetAttributeText (char *xmlNode, const char *xmlAttrName, char *xmlAttrValue, int xmlAttrValueSize);
char *XmlGetNodeText (char *xmlNode, char *xmlText, int xmlTextSize);
char *XmlFindElementByAttributeValue (char *xml, char *nodeName, const char *attrName, const char *attrValue);
char *XmlQuoteText (const char *textSrc, char *textDst, int textDstMaxSize);

#if !defined(_UEFI)
wchar_t *XmlQuoteTextW(const wchar_t *textSrc, wchar_t *textDst, int textDstMaxSize);

typedef struct {
	char *str;
	int   len; // used length
	int   size; // allocated size
} STRING;

int StrAppend(STRING* file, const char* str);

int XmlWriteHeader (STRING *file);
int XmlWriteFooter(STRING *file);

BOOL ReadConfigValue(char* configContent, const char *configKey, char *configValue, int maxValueSize);
int ReadConfigInteger(char* configContent, const char *configKey, int defaultValue);
__int64 ReadConfigInteger64(char* configContent, const char *configKey, __int64 defaultValue);
char *ReadConfigString(char* configContent, const char *configKey, char *defaultValue, char *str, int maxLen);
BOOL WriteConfigString(STRING* configFile, char* configContent, const char *configKey, const char *configValue);
BOOL WriteConfigInteger(STRING* configFile, char* configContent, const char *configKey, int configValue);
BOOL WriteConfigInteger64(STRING* configFile, char* configContent, const char *configKey, __int64 configValue);

#endif !defined(_UEFI)*/

#ifdef __cplusplus
}
#endif

#endif // _XML_H_