#include "storctl.h"
#include <memory>

bool verifyCertificate(const std::string& filePath)
{
  std::wstring filePathW(filePath.begin(), filePath.end());
  puts("Stage 2. Check file's signer certificate and hash");
  PCCERT_CONTEXT pccContext = NULL;
  HRESULT status = MsiGetFileSignatureInformationW(filePathW.c_str(), 0, &pccContext, NULL, NULL);
  std::unique_ptr<std::remove_pointer<PCCERT_CONTEXT>::type, void (*)(PCCERT_CONTEXT)> contextTerminator{pccContext, [](PCCERT_CONTEXT p)
                                                                                                         { ::CertFreeCertificateContext(p); }};

  switch (status)
  {
  case ERROR_SUCCESS:
    break;
  case TRUST_E_NOSIGNATURE:
    puts("File is not signed");
    return false;

  case TRUST_E_BAD_DIGEST:
    puts("The file's current hash is invalid according to the hash stored in the file's digital signature.");
    return false;

  case CERT_E_REVOKED:
    puts("The file's signer certificate has been revoked. The file's digital signature is compromised.");
    return false;

  case TRUST_E_SUBJECT_NOT_TRUSTED:
    puts("The subject failed the specified verification action."
         "Most trust providers return a more detailed error code that describes the reason for the failure.");
    return false;

  case TRUST_E_PROVIDER_UNKNOWN:
    puts("The trust provider is not recognized on this system.");
    return false;

  case TRUST_E_ACTION_UNKNOWN:
    puts("The trust provider does not support the specified action.");
    return false;

  case TRUST_E_SUBJECT_FORM_UNKNOWN:
    puts("The trust provider does not support the form specified for the subject");
    return false;
  default:
    printLastError();
    printf("Error is: 0x%x.\n", status);
  }

  DWORD size = ::CertGetNameStringW(pccContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
  if (size <= 1)
  {
    puts("failed to get certificate's name.");
    return false;
  }
  std::vector<wchar_t> buffer(size);
  ::CertGetNameStringW(pccContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, buffer.data(), size);

  std::wstring subject(buffer.data());
  
  printf("Certificate '%S' check OK\r\n", subject.c_str());
  return true;
}

bool verifyTrust(const std::string& filePath)
{  
  std::wstring filePathW(filePath.begin(), filePath.end());
  puts("Stage 1. Verify a file or object using the Authenticode policy provider.");
  WINTRUST_FILE_INFO FileData = {0};
  FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
  FileData.pcwszFilePath = filePathW.c_str();

  WINTRUST_DATA WinTrustData = {0};
  WinTrustData.cbStruct = sizeof(WinTrustData);
  WinTrustData.dwUIChoice = WTD_UI_NONE;
  WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
  WinTrustData.pFile = &FileData;
  WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

  GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

  LONG lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);
  DWORD dwLastError = 0;

  switch (lStatus)
  {
  case ERROR_SUCCESS:
    /*
    Signed file:
        - Hash that represents the subject is trusted.

        - Trusted publisher without any verification errors.

        - UI was disabled in dwUIChoice. No publisher or
            time stamp chain errors.

        - UI was enabled in dwUIChoice and the user clicked
            "Yes" when asked to install and run the signed
            subject.
    */
    printf("The file is signed and the signature "
           "was verified.\n");
    return true;

  case TRUST_E_NOSIGNATURE:
    // The file was not signed or had a signature
    // that was not valid.
    // Get the reason for no signature.
    dwLastError = GetLastError();
    if (TRUST_E_NOSIGNATURE == dwLastError ||
        TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
        TRUST_E_PROVIDER_UNKNOWN == dwLastError)
    {
      // The file was not signed.
      printf("The file is not signed.\n");
    }
    else
    {
      // The signature was not valid or there was an error
      // opening the file.
      printf("An unknown error occurred trying to "
             "verify the signature of the file."
             "The signature was not valid or there was an error opening the file.\n");
    }

    return false;

  case TRUST_E_EXPLICIT_DISTRUST:
    // The hash that represents the subject or the publisher
    // is not allowed by the admin or user.
    printf("The signature is present, but specifically "
           "disallowed.\n");
    return false;

  case TRUST_E_SUBJECT_NOT_TRUSTED:
    // The user clicked "No" when asked to install and run.
    printf("The signature is present, but not "
           "trusted.\n");
    return false;

  case CRYPT_E_SECURITY_SETTINGS:
    /*
    The hash that represents the subject or the publisher
    was not explicitly trusted by the admin and the
    admin policy has disabled user trust. No signature,
    publisher or time stamp errors.
    */
    printf("CRYPT_E_SECURITY_SETTINGS - The hash "
           "representing the subject or the publisher wasn't "
           "explicitly trusted by the admin and admin policy "
           "has disabled user trust. No signature, publisher "
           "or timestamp errors.\n");
    return false;

  default:
    // The UI was disabled in dwUIChoice or the admin policy
    // has disabled user trust. lStatus contains the
    // publisher or time stamp chain error.
    printLastError();
    printf("Error is: 0x%x.\n", lStatus);
    return false;
  }


  WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

  return true;
}