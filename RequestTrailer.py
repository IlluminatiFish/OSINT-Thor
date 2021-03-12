import requests, warnings, socket
from urllib.parse import urlparse

def gatherChain(url, verify_mode): #Gather the redirect chain of the url passed as a parameter

    response = None
    if verify_mode is False:
        response = requests.get(url, verify=False)
        print('[+] Attempting to gather redirect chain data mode: FALSE')

    if verify_mode is True:
        response = requests.get(url, verify=True)
        print('[+] Attempting to gather redirect chain data mode: TRUE')

    if response is not None:
        if response.history: #If the chain has any history
            print('  [+] Found {} redirects in chain'.format(len(response.history)))
            redirect = 0
            for resp in response.history:
                redirect += 1
                parser_object = urlparse(resp.url)
                if parser_object.netloc: #If domain is detected
                    try:
                        ip = socket.gethostbyname(parser_object.netloc) #Resolve to an IPv4
                    except:
                        ip = None #Will give a null IP if the domain cannot be resolved

                    print('    - [Redirect: {}] [IP: {}] [Status: {}] - {}'.format(redirect, ip, resp.status_code, resp.url))
                    #print('    [+] Response: ', str(resp.content).rstrip())
                else:
                    print('    [-] No netloc found in URL from request history')

            parser_object = urlparse(response.url)
            if parser_object.netloc: #If domain is detected
                try:
                    ip = socket.gethostbyname(parser_object.netloc)
                except:
                    ip = None
            print('  [Effective URL] [IP: {}] [Status: {}] - {}'.format(ip, response.status_code, response.url))
            #print('    [+] Response: ', str(resp.content).rstrip())
        else:
            print('[-] No request history found, no redirects')
    else:
        print('[-] Failed to set any gatherChain mode as request object was null')

def chainDiscover(url): #Run the gatherChain function, use false mode incase of an exception
    try: #Initially try with TRUE mode
        gatherChain(url, True)
    except requests.exceptions.SSLError as ex: #If TRUE mode errors then it'll fallback to FALSE
        print('[-] Failed to gather redirect chain data using mode: TRUE [Err: {}]'.format(ex.__doc__))
        warnings.filterwarnings("ignore")
        gatherChain(url, False)

url = input("[+] URL: ")
chainDiscover(url)
