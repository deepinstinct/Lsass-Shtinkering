# Lsass Shtinkering
New method of dumping LSASS by abusing the Windows Error Reporting service.
It sends a message to the service with the ALPC protocol to report an exception on LSASS.
This report will cause the service to dump the memory of LSASS.

## Prerequisites
The registry value "DumpType" under "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" should be set to 2.

## Credits

* [Asaf Gilboa](https://twitter.com/asaf_gilboa)

## References
- https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Asaf%20Gilboa%20-%20LSASS%20Shtinkering%20Abusing%20Windows%20Error%20Reporting%20to%20Dump%20LSASS.pdf
