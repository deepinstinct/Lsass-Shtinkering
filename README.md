# Lsass Shtinkering
New method of dumping LSASS by abusing the Windows Error Reporting service.
It sends a message to the service with the ALPC protocol to report an exception on LSASS.
This report will cause the service to dump the memory of LSASS.

## Prerequisites
The registry value "DumpType" under "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" should be set to 2.

## Credits

* [Asaf Gilboa](https://twitter.com/asaf_gilboa)