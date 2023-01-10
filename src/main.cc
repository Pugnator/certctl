/*
@brief   Tool for checking certificates
*/

#include "storctl.h"

const char *usageText = "Certificate control tool\n"
                        "\tcertctl --listloc                                          List system certificate locations\n"
                        "\tcertctl --liststores                                       List system certificate stores\n"
                        "\tcertctl --checkfile --file=[NAME]                          Check file signatures using Windows API\n"
                        "\tcertctl --liststore --store=[NAME]                         List certificates in the specified store\n"
                        "\tcertctl --getcert --store=[STORENAME] --cert=[CERTNAME]    Display certificate\n";

int usage()
{
  puts(usageText);
  return 1;
}

int main(int argc, char **argv)
{
  try
  {
    auto store = getCmdOption(argc, argv, "--store=");
    auto cert = getCmdOption(argc, argv, "--cert=");
    auto filename = getCmdOption(argc, argv, "--file=");

    bool listloc = cmdOptionExists(argv, argv + argc, "--listloc");
    if (listloc)
    {
      listStoreLocations();
      return 0;
    }

    bool liststores = cmdOptionExists(argv, argv + argc, "--liststores");
    if (liststores)
    {
      listAllStores();
      return 0;
    }

    bool liststore = cmdOptionExists(argv, argv + argc, "--liststore");
    if (liststore && !store.empty())
    {
      listStore(store);
      return 0;
    }

    bool getcert = cmdOptionExists(argv, argv + argc, "--getcert");
    if (getcert && !cert.empty() && !store.empty())
    {
      displayCertificate(store, cert);
      return 0;
    }

    bool checkfile = cmdOptionExists(argv, argv + argc, "--checkfile");
    if (checkfile && !filename.empty())
    {
      printf("Checking Windows trust for the file {%s}\r\n", filename.c_str());
      verifyTrust(filename);
      verifyCertificate(filename);
    }
  }
  catch (const std::runtime_error &e)
  {
    puts(e.what());
  }
  return usage();
}
