#include "storctl.h"

BOOL GetSystemName(
    const void* pvSystemStore,
    DWORD dwFlags,
    PENUM_ARG pEnumArg,
    LPCWSTR* ppwszSystemName)
{
  //-------------------------------------------------------------------
  // Declare local variables.

  *ppwszSystemName = NULL;

  if (pEnumArg->hKeyBase && 0 == (dwFlags &
                                  CERT_SYSTEM_STORE_RELOCATE_FLAG))
  {
    printf("Failed => RELOCATE_FLAG not set in callback. \n");
    return FALSE;
  }
  else
  {
    if (dwFlags & CERT_SYSTEM_STORE_RELOCATE_FLAG)
    {
      PCERT_SYSTEM_STORE_RELOCATE_PARA pRelocatePara;
      if (!pEnumArg->hKeyBase)
      {
        throw std::runtime_error("Failed => RELOCATE_FLAG is set in callback");
      }
      pRelocatePara = (PCERT_SYSTEM_STORE_RELOCATE_PARA)pvSystemStore;
      if (pRelocatePara->hKeyBase != pEnumArg->hKeyBase)
      {
        throw std::runtime_error("Wrong hKeyBase passed to callback");
      }
      *ppwszSystemName = pRelocatePara->pwszSystemStore;
    }
    else
    {
      *ppwszSystemName = (LPCWSTR)pvSystemStore;
    }
  }
  return TRUE;
}

void printLastError()
{
  DWORD errorMessageID = GetLastError();
  if (errorMessageID == 0)
  {
    puts("Success.");
  }

  LPSTR messageBuffer = nullptr;
  size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                               NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

  if (size)
  {
    puts(messageBuffer);
    LocalFree(messageBuffer);
  }
  else
  {
    puts("Failed to format error message.");
  }
}

std::string getCmdOption(int argc, char* argv[], const std::string& option)
{
  std::string cmd;
  for (int i = 0; i < argc; ++i)
  {
    std::string arg = argv[i];
    if (!arg.find(option))
    {
      size_t found = arg.find_first_of("=");
      return arg.substr(found + 1);
    }
  }
  return cmd;
}

bool cmdOptionExists(char** begin, char** end, const std::string& option)
{
  return std::find(begin, end, option) != end;
}