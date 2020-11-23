# FortiGate to CSV Converter

FortiGate web UI has no easy way to export a CSV, unless you also use FortiManager, so this script can be used to fetch JSON data over the REST API and export it as CSV.

Some common objects are included, but it should be easy to modify and extend to your requirements.

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
