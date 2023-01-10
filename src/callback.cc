#include "storctl.h"


BOOL WINAPI EnumSysCallback(const void* pvSystemStore, DWORD dwFlags, PCERT_SYSTEM_STORE_INFO pStoreInfo, void* pvReserved, void* pvArg)
{
  PENUM_ARG pEnumArg = (PENUM_ARG)pvArg;
  LPCWSTR pwszSystemStore;

  if (GetSystemName(pvSystemStore, dwFlags, pEnumArg, &pwszSystemStore))
  {
    wprintf(L"  '%s'\n", pwszSystemStore);
  }
  else
  {
    throw std::runtime_error("GetSystemName failed.");
  }

  if (pEnumArg->fAll || pEnumArg->fVerbose)
  {
    dwFlags &= CERT_SYSTEM_STORE_MASK;
    dwFlags |= pEnumArg->dwFlags & ~CERT_SYSTEM_STORE_MASK;
    if (!CertEnumPhysicalStore(pvSystemStore, dwFlags, pEnumArg, EnumPhyCallback))
    {
      DWORD dwErr = GetLastError();
      if (!(ERROR_FILE_NOT_FOUND == dwErr ||
            ERROR_NOT_SUPPORTED == dwErr))
      {
        printf("    CertEnumPhysicalStore");
      }
    }
  }
  return TRUE;
}

BOOL WINAPI EnumLocCallback(LPCWSTR pwszStoreLocation, DWORD dwFlags, void* pvReserved, void* pvArg)
{
  PENUM_ARG pEnumArg = (PENUM_ARG)pvArg;
  DWORD dwLocationID = (dwFlags & CERT_SYSTEM_STORE_LOCATION_MASK) >> CERT_SYSTEM_STORE_LOCATION_SHIFT;

  wprintf(L"======   '%s'   ======\n", pwszStoreLocation);

  if (pEnumArg->fAll)
  {
    dwFlags &= CERT_SYSTEM_STORE_MASK;
    dwFlags |= pEnumArg->dwFlags & ~CERT_SYSTEM_STORE_LOCATION_MASK;
    CertEnumSystemStore(dwFlags, (void*)pEnumArg->pvStoreLocationPara, pEnumArg, EnumSysCallback);
  }
  return TRUE;
}


BOOL WINAPI EnumPhyCallback(const void* pvSystemStore, DWORD dwFlags, LPCWSTR pwszStoreName, PCERT_PHYSICAL_STORE_INFO pStoreInfo, void* pvReserved, void* pvArg)
{
  PENUM_ARG pEnumArg = (PENUM_ARG)pvArg;
  LPCWSTR pwszSystemStore;

  if (GetSystemName(pvSystemStore, dwFlags, pEnumArg, &pwszSystemStore))
  {
    wprintf(L"    Store '%s'", pwszStoreName);
  }
  else
  {
    throw std::runtime_error("GetSystemName failed.");
  }
  if (pEnumArg->fVerbose && (dwFlags & CERT_PHYSICAL_STORE_PREDEFINED_ENUM_FLAG))
  {
    printf(" (implicitly created)");
  }

  printf("\n");
  return TRUE;
}
