#include "storctl.h"


void listAllStores()
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


  printf("\nBegin enumeration of system stores.\n");

  if (CertEnumSystemStore(dwFlags, pvStoreLocationPara, &EnumArg, EnumSysCallback))
  {
    printf("\nFinished enumerating system stores.\n");
  }
  else
  {
    throw std::runtime_error("Enumeration of system stores failed.");
  }

  printf("\n\nEnumerate the physical stores "
         "for the MY system store. \n");
  if (CertEnumPhysicalStore(L"MY", dwFlags, &EnumArg, EnumPhyCallback))
  {
    printf("Finished enumeration of the physical stores.\n");
  }
  else
  {
    throw std::runtime_error("Enumeration of physical stores failed.");
  }
}

void listStore(std::string& pszStoreName)
{
  HCERTSTORE hCertStore;
  if (!(hCertStore = CertOpenSystemStore(NULL, pszStoreName.c_str())))  
  {    
    throw std::runtime_error("The store was not opened.");
  }

  PCCERT_CONTEXT pCertContext = NULL;

  while (pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext))
  {
    wchar_t pszNameString[256];
    if (CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszNameString, 128))
    {
      wprintf(L"\nCertificate for '%s'\n", pszNameString);
    }
  }
}