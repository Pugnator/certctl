#include "storctl.h"


void listStoreLocations()
{
  DWORD dwFlags = 0;
  DWORD dwLocationID = CERT_SYSTEM_STORE_CURRENT_USER_ID;
  ENUM_ARG EnumArg;


  memset(&EnumArg, 0, sizeof(EnumArg));
  EnumArg.dwFlags = dwFlags;
  HKEY hKeyBase = NULL;
  void* pvStoreLocationPara = NULL;
  EnumArg.hKeyBase = hKeyBase;

  EnumArg.pvStoreLocationPara = pvStoreLocationPara;
  EnumArg.fAll = TRUE;
  dwFlags &= ~CERT_SYSTEM_STORE_LOCATION_MASK;
  dwFlags |= (dwLocationID << CERT_SYSTEM_STORE_LOCATION_SHIFT) & CERT_SYSTEM_STORE_LOCATION_MASK;


  printf("Begin enumeration of store locations.\n");
  if (CertEnumSystemStoreLocation(dwFlags, &EnumArg, EnumLocCallback))
  {
    printf("\nFinished enumerating locations.\n");
  }
  else
  {
    throw std::runtime_error("Enumeration of locations failed.");
  }
}