#pragma once

#include <Windows.h>
#include <msi.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <cryptuiapi.h>

#include <algorithm>
#include <vector>
#include <stdexcept>

#define WINTRUST_ACTION_GENERIC_VERIFY_V2           \
  {                                                 \
    0xaac56b,                                       \
        0xcd44,                                     \
        0x11d0,                                     \
    {                                               \
      0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee \
    }                                               \
  }

typedef struct _ENUM_ARG
{
  BOOL fAll;
  BOOL fVerbose;
  DWORD dwFlags;
  const void* pvStoreLocationPara;
  HKEY hKeyBase;
} ENUM_ARG, *PENUM_ARG;

BOOL WINAPI EnumPhyCallback(
    const void* pvSystemStore,
    DWORD dwFlags,
    LPCWSTR pwszStoreName,
    PCERT_PHYSICAL_STORE_INFO pStoreInfo,
    void* pvReserved,
    void* pvArg);

BOOL WINAPI EnumSysCallback(
    const void* pvSystemStore,
    DWORD dwFlags,
    PCERT_SYSTEM_STORE_INFO pStoreInfo,
    void* pvReserved,
    void* pvArg);

BOOL WINAPI EnumLocCallback(
    LPCWSTR pwszStoreLocation,
    DWORD dwFlags,
    void* pvReserved,
    void* pvArg);

BOOL GetSystemName(
    const void* pvSystemStore,
    DWORD dwFlags,
    PENUM_ARG pEnumArg,
    LPCWSTR* ppwszSystemName);

bool verifyTrust(const std::string&);
bool verifyCertificate(const std::string&);

void listAllStores();
void listStoreLocations();

void listStore(std::string&);
void displayCertificate(std::string& store, std::string& certname);

std::string getCmdOption(int argc, char* argv[], const std::string& option);
bool cmdOptionExists(char** begin, char** end, const std::string& option);
void printLastError();