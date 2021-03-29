//#include <openssl/des.h>
#include "moduls_check.h"
#include "md5.h"

char* GetMD5 (char* FileName)
{
  FILE* fInput;
  char* StrSum;
  char tmp[16] = "";
  unsigned char bBuffer[4096], digest[16];
  //Computer hash
  MD5_CTX md5;
  MD5Init (&md5);
  fInput = fopen (FileName, "rb");
  if (!fInput) {
    return "ERROR";
  }
  while (!feof (fInput)) {
    unsigned int nCount = fread (bBuffer, sizeof (unsigned char), 4096, fInput);
    MD5Update (&md5, bBuffer, nCount);
  }
  MD5Final (digest, &md5);
  if (fInput) fclose (fInput);
  //print hexdigest
  StrSum = (char*)malloc (300);
  memset (StrSum, 0, 300);
  for (int i = 0; i < 16; i++) {
    sprintf (tmp, "%02X", digest[i]);
    strcat (StrSum, tmp);
  }
  strcat (StrSum, "\0");
  return StrSum;
}