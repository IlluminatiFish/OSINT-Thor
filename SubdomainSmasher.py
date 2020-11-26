import censys.certificates
import socket
import requests
import ipaddress
import json

UID = "" #UID from censys.io api
SECRET = "" #SECRET from censys.io api

domain = input('[~] Pivot Domain: ')


#Function to get information on domain and/or ip
def get_info(datatype, data):
    if data is None:
        return
    else:
        url = "http://ip-api.com/json/{}".format(data)
        req = requests.get(url)
        try:
            reqjson = req.json()
        except json.decoder.JSONDecodeError as err:
            print('JSON Error, unable to gather info on ip/domain')
        if str(datatype) == "ISP":
            try:
                isp = reqjson['isp']
                if len(isp) == 0:
                    isp = None
            except KeyError:
                isp = None
            return isp
        if str(datatype) == "ASN":
            try:
                asn = reqjson['as']
                if len(asn) == 0:
                    asn = None
            except KeyError:
                asn = None
            return asn
        if str(datatype) == "ORG":
            try:
                org = reqjson['org']
                if len(org) == 0:
                    org = None
            except KeyError:
                org = None
            return org

######################################

#Gather IPv4 tcpshield ranges to filter them out of the results
def get_tcpshield_v4_ranges():
    url = 'https://tcpshield.com/v4'
    request = requests.get(url)
    tcp_shield_ranges = (request.text).splitlines()
    return tcp_shield_ranges



#Gather IPv4 cloudflare ranges to filter them out of the results
def get_cloudflare_v4_ranges():
    url = 'https://www.cloudflare.com/ips-v4'
    request = requests.get(url)
    cloudflare_ranges = (request.text).splitlines()
    return cloudflare_ranges

#Check if param ip address is tcpshield
def check_tcpshield(ip):
    if ip != "ERR::FAILED_RES" and ip != "ERR::PRIV_IP": # Solves issues of having private IP addresses as results.
        ip_object = ipaddress.ip_address(ip)
        for cidr in get_tcpshield_v4_ranges():
            cidr_object = ipaddress.ip_network(cidr)
            if ip_object in cidr_object:
                return True
                #print('[-] {} is a TCPShield IP'.format(ip))

#Check if param ip address is cloudflare
def check_cloudflare(ip):
    if ip != "ERR::FAILED_RES" and ip != "ERR::PRIV_IP": # Solves issues of having private IP addresses as results.
        ip_object = ipaddress.ip_address(ip)
        for cidr in get_cloudflare_v4_ranges():
            cidr_object = ipaddress.ip_network(cidr)
            if ip_object in cidr_object:
                return True
                #print('[-] {} is a Cloudflare IP'.format(ip))


##### USING CENSYS.IO TO ENUMERATE SUBDOMAINS FROM SSL CERTS #####
def subdomain_find(domain, censys_id, censys_secret):
    try:
        censys_cert = censys.certificates.CensysCertificates(api_id=censys_id,api_secret=censys_secret) #Create censys cert object
        cert_query = 'parsed.names: %s' % domain #Genreate censys search query
        cert_search_results = censys_cert.search(cert_query, fields=['parsed.names']) #Search using the censys cert object
 
        subdomains = [] #List of subdomains
        for result in cert_search_results: #Iterate over the results from Censys
            subdomains.extend(result['parsed.names']) #Extend list with parsed.names results from the API

        
        return set(subdomains) #removes duplicate values
        
    except censys.base.CensysUnauthorizedException: #Catch censys api based errors
        print('[+] Censys.IO credentials are invalid \n')
    except censys.base.CensysRateLimitExceededException:
        print('[+] Rate limit exceeded.')


def subdomain_filter(domain,subdomains): #If the subdomain is *.domain.com, it will filter it out from the list of subdomains.
    return [ subdomain for subdomain in subdomains if '*' not in subdomain and subdomain.endswith(domain) ]


def subdomains_list(domain, subdomains): #Take the list and show it in a structured way.
    possibilities = []
    
    if len(subdomains) == 0:
        print('[-] Did not find any subdomain')
        return
    
    print('')
    print('[+] Found %d unique subdomain(s)' % (len(subdomains)))
    count = 1
    for subdomain in subdomains:
        try:
            raw_ip = socket.gethostbyname(subdomain)
            if ipaddress.ip_address(raw_ip).is_global: # Solves issues of having private IP addresses as results.
                ip = raw_ip
            else:
                ip = 'ERR::PRIV_IP' # Solves issues of having private IP addresses as results.
        except socket.gaierror:
            ip = 'ERR::FAILED_RES'

 
        if check_tcpshield(ip):
            print(' [{}] {} - (ERR::TCP_SHIELD_FOUND)'.format(count, subdomain, ip))
        elif check_cloudflare(ip):
            print(' [{}] {} - (ERR::CLOUDFLARE_FOUND)'.format(count, subdomain, ip))
        elif ip == "ERR::FAILED_RES":
            print(' [{}] {} - ({})'.format(count, subdomain, ip))
        else:
            print(' [{}*] {} - ({})'.format(count, subdomain, ip))
            possibilities.append(ip)
            
        count += 1
     
    print('')
    if len(possibilities) > 0:
        print('[+] Possible Server Direct IPs ({}):'.format(len(set(possibilities))))
        count_possible = 1
        for possible in set(possibilities):
            print(' [{}] {} ({}, {}, {})'.format(count_possible, possible, get_info("ASN", possible), get_info("ISP", possible), get_info("ORG", possible)))
            count_possible += 1
    else:
        print('[+] No possbile direct server IPs were found')
##################################################################################

#Main driver code here
found = subdomain_find(domain, UID, SECRET)
filtered = subdomain_filter(domain, found)
subdomains_list(domain, filtered)
