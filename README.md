# ESXi-6.7-STIG-V1R1
This script is used to STIG an ESXI 6.7 host according to DISA's most recent ESXi 6.7 STIG V1R1.

When this script is ran, the target ESXi host will have all of the "Get" commands from the STIG executed and the outputs will be stored in an ESXi 6.7 STIG checklist.
All of the associated 'Findings' or 'Not A Findings' will be updated in this output checklist, of course.

I use this when we have a new ESXi host in our environment or when we've recently upgraded a 6.5 host to 6.7 and need to apply an entirely new STIG. 
Most of the items are included in what this script checks, but not all. Some of the ambiguous items can't really be automated.


*** WARNING: For the SSH commands required in the STIG, the script will create an SSH key locally, send to the target server, and OVERWRITE the authorized_keys file on the target server. This authorized_keys file will then be REMOVED from the ESXi host. Comment this section out if you already have a shared key with target server***

I recommend testing in a lab environment beforehand so you're familiar with what happens during the script process. 


REQUIREMENTS:
- Blank ESXi 6.7 STIG checklist
- Administrator permissions on ESXi host

HOW TO USE:
- Execute script, follow prompts
- Output checklist will be created in directory chosen by user
