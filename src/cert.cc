#include "storctl.h"

void displayCertificate(std::string& store, std::string& certname)
{
  HCERTSTORE hCertStore;
  if (!(hCertStore = CertOpenSystemStore(NULL, store.c_str())))
  {
    throw std::runtime_error("The store was not opened.");
  }

  PCCERT_CONTEXT pCertContext = NULL;

  while (pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext))
  {
    wchar_t pszNameString[256];
    if (CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszNameString, 128))
    {
      //if (!wcscmp(pszNameString, certname.c_str()))
      {
        if (!CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT, pCertContext, NULL, NULL, 0, NULL))
        {
          throw std::runtime_error("UI failed.");
        }
      }
    }
  }
}