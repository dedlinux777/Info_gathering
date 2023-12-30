import socket
import sys
import whois
import dns.resolver
import shodan
import requests
import argparse
from censys.search import SearchClient
from dns.rdatatype import CNAME

# create object of argparse
parser = argparse.ArgumentParser(description="This is a basic information gathering tool by Dedlinux",
                                 usage="python3 info_gathering.py -d DOMAIN[-s IP]")
# add short and long arguments to the object
parser.add_argument('-d', '--domain', help="Enter Domain for gather information about domain")
parser.add_argument('-s', '--ip_search', help="Enter IP address for shodan and censys search")
parser.add_argument('-i', '--get_host_ip', help="Enter domain_name only to get Host_IP,")
parser.add_argument('-n', '--get_host_name', help="Enter IP address only to get Host_Name")
parser.add_argument('-o', '--output', help="Enter file for saving the output")
# fetch users input/values into a var or parsing into a var
args = parser.parse_args()
# the stored values/fetched attributes can be used like this:
domain = args.domain
IP = args.ip_search
get_host_ip = args.get_host_ip
get_host_name = args.get_host_name
output = args.output

#get IP from domain
if get_host_ip:
    IP_addr_of_name  = socket.gethostbyname(get_host_ip)
    print("[+]The IP address of the domain name you entered is = ", IP_addr_of_name)

#get Host_name from IP
if get_host_name:
    Host_name_of_IP = socket.gethostbyaddr(get_host_name)
    print("[+]The Host_Name of the IP address you have entered is =", Host_name_of_IP)

# whois block, using whois library, query using whois.query on a domain to get domain basic information
if domain:
    print("[+] Getting whois information about the domain")
    whois_results = " "
    try:
        wh = whois.query(domain)
        whois_results += ("name = {}\n".format(wh.name))
        whois_results += ("registrar = {}\n".format(wh.registrar))
        whois_results += ("expiration_date = {}\n".format(wh.expiration_date))
        whois_results += ("last_updated = {}\n".format(wh.last_updated))
    except Exception as e:
        print("An exception occurred:", e)
    print(whois_results)

# dns module using dns.resolver
if domain:
    print("[+]Getting DNS Records Information of IP or Domain...")
    # using dns.resolver from dnspython
    dns_results = " "
    if domain:
        try:
# in var a resolve A records from dns using dns.resolver.resolve method, so as the records must be in any type using to_text to add in a var and same for remaining records
            for a in dns.resolver.resolve(domain, 'A'):
                dns_results += ("[+] A records: {}\n".format(a.to_text()))
        except Exception as e:
            print("Error in A records:", e)
        try:
            for ns in dns.resolver.resolve(domain, 'NS'):
                dns_results += ("[+] NS Records: {}\n".format(ns.to_text()))
        except Exception as e:
            print("Error in ns records:", e)
        try:
            for mx in dns.resolver.resolve(domain, 'MX'):
                dns_results += ("[+] MX Records: {}\n".format(mx.to_text()))
        except Exception as e:
            print("Error in mx records:", e)
        try:
            for txt in dns.resolver.resolve(domain, 'TXT'):
                dns_results += ("[+] txt Records: {}\n".format(txt.to_text()))
        except Exception as e:
            print("Error in txt records:", e)
        try:
            for cname in dns.resolver.resolve(domain, 'CNAME'):
                dns_results += f"[+] CNAME Records: {CNAME.to_text()}\n"
        except Exception as e:
            print("Error in CNAME records:", e)
        try:
            for PTR in dns.resolver.resolve(domain, 'PTR'):
                dns_results += ("[+] PTR Records: {}\n".format(PTR.to_text()))
        except Exception as e:
            print("Error in PTR records:", e)
        try:
            for soa in dns.resolver.resolve(domain, 'SOA'):
                dns_results += ("[+] soa Records: {}\n".format(soa.to_text()))
        except Exception as e:
            print("Error in soa records:", e)
        try:
            for srv in dns.resolver.resolve(domain, 'SRV'):
                dns_results += ("[+] srv Records: {}\n".format(srv.to_text()))
        except Exception as e:
            print("Error in srv records:", e)
        print(dns_results)

# geolocation block using the requests lib for using web requests and web requests manipulation
if domain:
    print("[+] Getting DNS/IP GeoLocation")
    geol_results = " "
#if domain given the get the Ip from it using socket.gethostbyname method and then get the response from web service https://geolocation-db.com/json/ using request GET and it will be in json so convert it into dictionary or a format to add in a var, here I used json() function to get this
#in responce we get the basic geo location information of domain so that adding in geol_results
    try:
        ip_address = socket.gethostbyname(domain)
        response = requests.request("get", f"https://geolocation-db.com/json/{ip_address}").json()
    except Exception as e:
        print("Got error in response by the domain or IP : ", e)
    try:
        geol_results += ("[+] Country: {}\n".format(response['country_name']))
    except Exception as e:
        print("failed to fetch Country name \n")
    try:
        geol_results += ("[+] State: {}\n".format(response['state']))
    except Exception as e:
        print("failed to fetch state name \n")
    try:
        geol_results += ("[+] City: {}\n".format(response['city']))
    except Exception as e:
        print("failed to fetch City name \n")
    try:
        geol_results += ("[+] Latitude: {}\n".format(response['latitude']))
    except Exception as e:
        print("failed to get Latitude of target \n")
    try:
        geol_results += ("[+] Longitude: {}\n".format(response['longitude']))
    except Exception as e:
        print("failed to get Longitude of target \n")
    print(geol_results)

#shodan module block
if IP:
    print("[+] Getting Shodan search results for the IP")
    shodan_results = " "
    #shodan API
    api = shodan.Shodan("fXsu2oHkOMiOtmFmYaABPvjqilnqrBrD")
    try:
        #conduct apt.search for the IP given for shodan search and make the format into dictionaries to add it into a var or printable
        results = api.search(IP)
        shodan_results += ("[+] results found: {}".format(shodan_results['total']))
        for resu in results['matches']:
            shodan_results += ("[+] IP: {}".format(resu['ip_string']))
            shodan_results += ("[+] data: {}".format(resu['data']))
    except Exception as e:
        print("Shodan search failed:", e)
    print(shodan_results)

#censys module block
#initialize the API ID and API secret key in a var and do a query to get results
if IP:
    print("[+] Getting censys search results")
    censys_results = [ ]
    API_ID = "c40ef29f-b1c6-48d8-b6a1-d4188f7b93eb"
    API_SECRET = "s7jsh9lsXLGff8rUz1xv7Z4Lt8oxuXFe"
    try:
        # Initialize Censys SearchClient
        c = SearchClient(API_ID, API_SECRET)
        # Perform a search query for the provided IP address
        query = IP
        # Search hosts based on the query
        for result_c in c.v2.hosts.search(query):
            censys_results.append(result_c)
    except Exception as e:
        print("An error occurred while performing censys search:", e)
    print(censys_results)

#output module block
if (output):
    with open(output, 'w') as file:
        file.write(whois_results + '\n\n')
        file.write(dns_results + '\n\n')
        file.write(geol_results + '\n\n')
        file.write(shodan_results + '\n\n')
        # Write censys_results line by line
        for result in censys_results:
            file.write(str(result) + '\n\n')
print("<<<< Thank you for using my dedlinux info_gathering script Happy Penetration Testing >>>>")
