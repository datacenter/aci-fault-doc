aci-fault-doc
=============
Author: Phillip Ferrell (phferrel@cisco.com)

# Description
Script to query APIC for faults and summarize corrective actions based on fault documentation on APIC

# Installation

## Environment
Required
* Python 2.7+
* Beautiful Soup 4 (bs4)


# Usage
Script requires access to APIC to query current faultInst MOs and documentation.  It also provides an option to pull fault documentation for a saved faultInst json query (/api/class/faultInst.json).

<pre>
usage: aci-fault-doc.py [-h] [--username USERNAME] [--pwd PWD] [--json JSON]
                        apicUrl

APIC Fault summary

positional arguments:
  apicUrl              APIC URL (http or https should be included)

optional arguments:
  -h, --help           show this help message and exit
  --username USERNAME  username
  --pwd PWD            password
  --json JSON          load faults from json file (expects full json response
                       by APIC)
</pre>
# Example
<pre>
[user@localhost ~]$ ./aci-fault-doc.py http://172.18.118.5 --user admin
Password: 

FAULT SUMMARY (grouped / sorted by # of occurrences)
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

FAULT: F0546, NAME: fltEthpmIfPortDownNoInfra, occurred: 3
FAULT: F607575, occurred: 2
FAULT: F606434, occurred: 2
FAULT: F1410, NAME: fltInfraClSzEqObstClusterSizeEqualization, occurred: 2
FAULT: F1371, NAME: fltPconsRADeploymentStatus, occurred: 2
FAULT: F1239, NAME: fltFabricLinkFailed, occurred: 2
FAULT: F0475, NAME: fltTunnelIfDestUnreach, occurred: 2
FAULT: F0454, NAME: fltLldpIfPortOutofService, occurred: 2
FAULT: F1240, NAME: fltVzTabooConfigurationFailed, occurred: 1
FAULT: F107496, occurred: 1
FAULT: F0523, NAME: fltFvATgConfigurationFailed, occurred: 1
FAULT: F0321, NAME: fltInfraWiNodeHealth, occurred: 1

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

FAULT DOCUMENTATION (grouped / sorted by # of occurrences)
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

FAULT: F0546 - 3 occurrences
    Fault Name: fltEthpmIfPortDownNoInfra
    Message: Port is down, reason operStQual , used by usage
    Severity: warning 
    Type: communications 
    Cause: port-failure 
    Explanation: 
       This fault occurs when a port is unconnected and is not in use for infra 
       
    Recommended Action: 
       To recover from this fault, try the following actions 
       
       Check the port connectivity 
       Remove the configuration or administratively shut the port if the port is not in use 

    Instances (first 10):
        warning topology/pod-1/node-104/sys/phys-[eth1/2]/phys/fault-F0546
            Port is down, reason:link-failure, used by:discovery
        warning topology/pod-1/node-101/sys/phys-[eth1/2]/phys/fault-F0546
            Port is down, reason:sfp-missing, used by:discovery
        warning topology/pod-1/node-102/sys/phys-[eth1/2]/phys/fault-F0546
            Port is down, reason:sfp-missing, used by:discovery

...remaining output ommitted
</pre>
# License

Copyright (C) 2014 Cisco Systems Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
