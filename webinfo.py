#!/usr/bin/python

import socket
import ssl
import datetime
import requests

class Clr:
    #Text colors

    RST = '\033[39m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'

class grab_banner():

     
     
    def __init__(self, host, port):
        
        #socket.setdefaulttimeout(3)
        #s = socket.socket()
        #s.connect((host, port))
        
        #print host
        response = requests.get(host) 
  
        # print response 
        print(response) 
  
        #print headers of response
        print(response.headers)
        '''
        print('{}[+] {}{}{}\n{}'.format(Clr.GREEN, host, Clr.GREEN, Clr.RST , '-' * (len(host)+53)))
        socket.setdefaulttimeout(3)
        s = socket.socket()
        s.connect((host, port))
        s.send('GET HEAD/1.1\nHost: ' + host + '\n\n')
        print('{}Banner : {}'.format(Clr.YELLOW, Clr.RST))
        print s.recv(1024)
        print ('-------------------------------------------------------------')
        s.close()'''


class sslchecker():

    def filter_hostname(self, host):
        """Remove unused characters and split by address and port."""
        host = host.replace('http://', '').replace('https://', '').replace('/', '')

        return host

    def get_cert(self, host, port):
        
        
        #filter_hostname()
        #set date format
        self.filter_hostname(host)
        ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
        #set context
        context = ssl.create_default_context()
        #to wrap a socket
        conn = context.wrap_socket(socket.socket(socket.AF_INET),server_hostname=host,)
        conn.settimeout(3)
        conn.connect((host, port))
        ssl_info = conn.getpeercert()
        if conn.getpeercert(True) :
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
        else:
            print ('No Certificate Found')


target = [raw_input('Key in Hostname : ')]
tport = [input('Key in Port : ')]

#map(grab_banner, target, tport)
#map(sslchecker, target, tport)

getcert = sslchecker(target, tport)
getcert.get_cert(target, tport)





 

