# SearchSubdomains

Search for all available subdomains using the certificate used or even using [virustotal](https://www.virustotal.com/gui/home/upload).

## Settings
This script relies on [censys.io](https://censys.io/) to work, so create a free account and get the API information.
To create an account you can use a temporary email.

```
apid: 'APPID'
secret: 'SECRETID'
```

If you know your public IP CIDR and would like to know which subdomains are within your network, mark `checkcidr` as` True`, and provide your CIDR as the example below:

```
CIDR:
  - group:
      name: 'MyCIDR'
      id: '10.1.0.0/24,10.0.0.0/24'
```
## Usage

To use the script create a file with all the domains you want to discover, one below the other, like the following example:


```
google.com.br
terra.com.br
```

After creating your file, use the following command to get started.


```
python SplunkSubDomains.py --config utils\config\config.yml --target target.txt
```

## Output

```
{  
   "domain":"petrobras.com.br",
   "type":"Public",
   "subdomain":"medusa.petrobras.com.br",
   "local":"Null",
   "status_code":"404",
   "ipv4":"164.85.66.15",
   "autonomous_system_number":"ASN23074",
   "autonomous_system_organization":"Petróleo Brasileiro S/A - Petrobras",
   "iso_code":"BR",
   "country_name":"Brazil",
   "most_specific":"Null",
   "city_name":"Null",
   "latitude":-22.8305,
   "longitude":-43.2192
}
```

