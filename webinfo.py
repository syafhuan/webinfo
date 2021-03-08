#!/usr/bin/python

import requests
import ssl
import datetime
import socket

class Clr:
    #Text colors

    RST = '\033[39m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'

class sslchecker():

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def filter_hostname(self):

        host = self.host.replace('http://', '').replace('https://', '').replace('/', '')

        return host

    def add_protocol(self):

        host = self.host
        port = self.port

        x = '://'
        '''
        for x in range(len(host)):
            if host[x] has ":":
    
                    return host
                
            else:
                if port == 80:
                    return ('http://'+host)
                if port == 443:
                    return ('https://'+host)'''
        if x in host:
            return host
        else:
            if port == 80:
                return ('http://'+host)
            if port == 443:
                return ('https://'+host)


    def grab_banner(self):


        host = self.add_protocol()

        response = requests.get(host) 
  
        print('{}[+] {}{}{}\n{}'.format(Clr.GREEN, host, Clr.GREEN, Clr.RST , '-------------------------------------------------------------'))
        print ('{}Header {}'.format(Clr.YELLOW, Clr.RST))

        print(response) 
  
        #print(response.headers)

        header_info = response.headers
        #print (header_info)

        connect =  header_info['Connection']
        con_language = header_info['Content-Language']
        con_encode = header_info['Content-Encoding']
        server = header_info['Server']
        allow_origin = header_info['Access-Control-Allow-Origin']
        con_type = header_info['Content-Type']

        print ('Connection: %s\nContent-Type: %s\nAccess-Control-Allow-Origin: %s\nServer: %s\nAccept-Encoding: %s\nAccept-Language: %s') %(connect, con_type, allow_origin, server, con_encode, con_language)
        print ('-------------------------------------------------------------')

    def get_cert(self):

        host = self.filter_hostname()
        port = self.port
        #self.filter_hostname()
        ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
        #set context
        try:
            context = ssl.create_default_context()
            #to wrap a socket
            conn = context.wrap_socket(socket.socket(socket.AF_INET),server_hostname=host,)
            conn.settimeout(3)
            conn.connect((host, port))
            ssl_info = conn.getpeercert()
        
            subject = dict(x[0] for x in ssl_info['subject'])
            issuerRemove = dict(x[0] for x in ssl_info['issuer'])
        
            issuer = issuerRemove['commonName']
            issueTo = subject['commonName']
            version = ssl_info['version']
            Start_Date = datetime.datetime.strptime(ssl_info['notBefore'], ssl_date_fmt)
            Last_Date = datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)
            Days_Remaining = Last_Date - datetime.datetime.utcnow()
            print ('{}SSL Certificate {}'.format(Clr.YELLOW,Clr.RST))
            print ('Issued By: %s\nIssued To: %s\nVersion: %s') %(issuer, issueTo, version)
            print ('Not Valid Before: %s\nNot Valid After: %s\nRemaining: %s') %(Start_Date, Last_Date, Days_Remaining)
            print ('-------------------------------------------------------------')
        #print (ssl_info)
        except Exception as error:
            print ('{}SSL Certificate {}'.format(Clr.YELLOW,Clr.RST))
            print ('No Certificate Found')
            print ('-------------------------------------------------------------')


def main():
    target = raw_input('Key in Hostname : ')
    tport = input('Key in Port : ')

    tHost = sslchecker(target, tport)

    #print ('Host : '), tHost.filter_hostname()
    tHost.grab_banner()
    tHost.get_cert()

main()


