# FortiGate to CSV Converter

If you use FortiGate, there's no easy way to export a CSV (with the exception of using FortiManager), so this script can be used to fetch JSON data over the REST API and export a CSV to a file.

Some sensible items and headers are included, but it should be easy to modify and extend as required.

## Usage

Command line arguments

* `-f` - Firewall IP/FQDN
* `-u` - Username
* `-v` - VDOM
* `-i` - Items *(interface, policy, snat, address, service, dnat, pool)*
* `-o` - CSV Outfile *(optional)*

### Example

```bash
% python fortigate2csv.py -f 1.2.3.4 -u dan -v management -i address -o address.csv
Connecting to 1.2.3.4 (management) as dan
Successfully logged in as dan
Fetching data...
Logging out of firewall
Saving to address.csv
Done!
```

Output:

```
name,type,subnet,fqdn,associated-interface,visibility,allow-routing,comment
hst-1,ipmask,10.10.10.1 255.255.255.255,,v123,enable,disable,description of host 1
hst-2,ipmask,10.10.10.2 255.255.255.255,,v123,enable,disable,description of host 2
login.microsoft.com,fqdn,,login.microsoft.com,,enable,disable,comment goes here
...
```
