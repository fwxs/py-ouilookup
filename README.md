# py-ouilookup
Looks up the **OUI** of the provided mac address, using the [linux.ca](https://linuxnet.ca/ieee/oui) _nmap-mac-prefixes_ file.

# Usage

```
ouilookup.py 00:11:22:33:44:55

[*] Found vendor: 00:11:22 -> Vendor
```
OR
```
ouilookup.py FF:11:FF:33:44:55
[*] Vendor not found.
```

# Internals

The script gets the first 24-bits of the MAC address (OUI), search it in the **oui.db** database and prints
the vendor name. If the **oui.db** file doesn't exists, it downloads the _nmap-mac-prefixes_ file from [linux.ca](https://linuxnet.ca/ieee/oui), reads it and then store the OUI and its respective vendor name on a sqlite database.
