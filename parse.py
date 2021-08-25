#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
#Nombre: Celia Lijo Soria
import os, sys, json
from optparse import OptionParser
import xml.etree.ElementTree as ET
import warnings
import textTohtml
import htmlTopdf

warnings.filterwarnings("ignore")

#variables globales
dir_nmap_tcp = "NMAP/nmap_TCP_full.xml"
dir_nmap_udp = "NMAP/nmap_UDP_top-50.xml"
dir_ssh = "SSH/ssh"
dir_testssl = "WEB/TLS/testssl_"
dir_dirsearch = "WEB/FUZZING/dirsearch_"
modo_agresivo = False

ipsList = []
ipsList_ordenada = []

SSHlist = []
TLSlist = []
SMBlist = []
FTPlist = []
TLNTlist = []
HTTPlist = []

def leer_fich(fich):
    datos=""
    if os.path.isfile(fich):
        f = open(fich)
        datos = f.read()
        f.close()
    return datos

def aniade_vulns_ordenadas(lista, num_criticas , num_altas, num_medias, num_bajas, num_info):
    vulnList = []
    if num_criticas != 0:
        for vuln in lista.vulnerabilidades:
            if vuln.cvss == 10:
                vulnList.append(vuln)
    if num_altas != 0:
        for vuln in lista.vulnerabilidades:
            if vuln.cvss == 7:
                vulnList.append(vuln)
    if num_medias != 0:
        for vuln in lista.vulnerabilidades:
            if vuln.cvss == 5:
                vulnList.append(vuln)
    if num_bajas != 0:
        for vuln in lista.vulnerabilidades:
            if vuln.cvss == 3:
                vulnList.append(vuln)
    if num_info != 0:
        for vuln in lista.vulnerabilidades:
            if vuln.cvss == 0:
                vulnList.append(vuln)

    data = textTohtml.Ip(lista.ip, vulnList, lista.data_ports, lista.directories)
    ipsList_ordenada.append(data)

def ordenar_ipsList():

    for item in ipsList:
        num_criticas = 0
        num_altas = 0
        num_medias = 0
        num_bajas = 0
        num_info = 0

        for vul in item.vulnerabilidades:
            if vul.severidad.upper() == "CRITICAL":
                num_criticas = num_criticas + 1
            elif vul.severidad.upper() == "HIGH":
                num_altas = num_altas + 1
            elif vul.severidad.upper() == "MEDIUM":
                num_medias = num_medias + 1
            elif vul.severidad.upper() == "LOW":
                num_bajas = num_bajas + 1
            else:
                num_info = num_info + 1

        aniade_vulns_ordenadas(item, num_criticas , num_altas, num_medias, num_bajas, num_info)

def imprimir_ipsList (lista):
    num_vulns = 0
    num_ips = 0
    
    for elem in lista:
        num_ports = 0
        num_ips = num_ips + 1
        print("\n* " + elem.ip + " *")
        print("\nList of vulnerabilities:\n")
        for vul in elem.vulnerabilidades:
            num_vulns = num_vulns + 1
            print(str(num_vulns) + ". " + vul.titulo + ": " + vul.descripcion)

        print("\nList of ports:\n")
        for port in elem.data_ports:
            num_ports = num_ports + 1
            print(str(num_ports) + ". " + port.protocol + " - " + port.port + " - " + port.service)

        
        if len(elem.directories) > 0:
            print("\nList of web directories:")
            for iteration,it in enumerate(elem.directories):
                num_dir = 0
                print("\n* Port " + it.port + ":")
                print("\n   HTTP_STATE  LENGHT    DIR     REDIR")
                for i in it.list_directories:
                    num_dir = num_dir + 1
                    print(str(num_dir) + ".    " + str(i.HTTPResponse) + "    -  " + i.content_lenght + "  - " + i.dir + " -  " + i.redir)

    print("\nHay "+ str(num_ips) + " IPs con " + str(num_vulns) + " vulnerabilidades")

def aniadir_dir(ip, puerto, listdir):
    dirList = []
    dir = ""
    existe_ip = False
    pos_ip = 0

    if len(listdir) > 0:
        dir = textTohtml.Directories(puerto, listdir)
        dirList.append(dir)

        for iteration,item in enumerate(ipsList):
            if item.ip == ip:
                existe_ip = True
                pos_ip = iteration
                break

        if existe_ip:
            ipsList[pos_ip].directories.extend(dirList)
        else:
            data = textTohtml.Ip(ip, vulnList, portList, dirList)
            ipsList.append(data)

def parse_fuzzing():
    for host in HTTPlist:
        listdir = []
        li = ""
        h = host.split(":")
        datos=leer_fich(dir_dirsearch + h[0] + "_p" + h[1] + ".json")
        if datos!="":
            dt=json.loads(datos)
            for r in dt['results']:
                for w in r['http://'+h[0]+':'+h[1]+'/']:
                    if w['status'] >= 300 and w['status'] <= 399:
                        li = textTohtml.ListDirectories("GET", w['status'], str(w['content-length']) + "B", w['path'],  w['redirect'])   
                    else:
                        li = textTohtml.ListDirectories("GET", w['status'], str(w['content-length']) + "B", w['path'],  "-") 
                    listdir.append(li)
            aniadir_dir(h[0], h[1], listdir)

def get_cvss (severidad):
    cvss = 0
    if severidad == "CRITICAL":
        cvss = 10
    elif severidad == "HIGH":
        cvss = 7
    elif severidad == "MEDIUM":
        cvss = 5
    elif severidad == "LOW":
        cvss = 3

    return(cvss)

def aniadir_vuln(vuelta, ip, puerto, severidad, cve, cwe, titulo, descripcion):
    vulnList = []
    portList = []
    dirList = []
    existe_ip = False
    pos_ip = 0
    vuln = ""

    vuln = textTohtml.Vulnerabilidad(get_cvss(severidad), severidad, puerto, cve, cwe, titulo, descripcion)
    vulnList.append(vuln)

    if vuelta > 0:
        for iteration,item in enumerate(ipsList):
            if item.ip == ip:
                existe_ip = True
                pos_ip = iteration
                break
        if existe_ip:
            ipsList[pos_ip].vulnerabilidades.extend(vulnList)
        else:
            data = textTohtml.Ip(ip, vulnList, portList, dirList)
            ipsList.append(data)
    elif vuln != "":
        data = textTohtml.Ip(ip, vulnList, portList, dirList)
        ipsList.append(data)


def parse_telnet():

    for host in TLNTlist:
        h = host.split(":")
        datos=leer_fich("TELNET/data_telnet_" + h[0] + "_p" + h[1] + ".txt")  
        telnet_creds = []
        credential =  False
        version = ""

        if datos!="": 
            datos = datos.split("\n")
            for linea in datos:       
                atrib = linea.split(" ")   
                if "[32m[+]" in atrib[0]:
                    for i in atrib:
                        if i=="Login Successful:":
                            credential =  True
                            break

                    if credential and len(atrib) == 7:
                        telnet_creds.append(atrib[6])
                    elif credential == False:
                        atrib = linea.split("-") 
                        version = atrib[1].replace(host,"")

            if len(telnet_creds) > 0:
                creds = "The following valid credentials have been listed:"
                for i in telnet_creds:
                    creds = creds + "\n" + i
                aniadir_vuln(1, h[0], h[1], "HIGH", "-",  "-", "Known telnet credentials", creds)
            
            if version != "":
                aniadir_vuln(1, h[0], h[1], "LOW", "-",  "-", "Known telnet version", version)


def parse_ftp():

    for host in FTPlist:
        h = host.split(":")
        datos=leer_fich("FTP/data_ftp_" + h[0] + "_p" + h[1] + ".txt")  
        ftp_creds = []
        
        if datos!="": 
            datos = datos.split("\n")
            for linea in datos:
                atrib = linea.split(" ")         
                if "[32m[+]" in atrib[0]:
                    if "Anonymous READ" in linea:
                        aniadir_vuln(1, h[0], h[1], "MEDIUM", "-",  "-", "Anonymous FTP is enabled", "-")
                    elif "FTP Banner:" in linea:
                        l = linea.split("'")
                        aniadir_vuln(1, h[0], h[1], "LOW", "-",  "-", "Known ftp version", l[1])
                    elif "Login Successful:" in linea:
                        atrib = linea.split(" ")
                        l = len(atrib)
                        ftp_creds.append(atrib[l-1])

            if len(ftp_creds) > 0:
                creds = "The following valid credentials have been listed:"
                for i in ftp_creds:
                    creds = creds + "\n" + i 
                aniadir_vuln(1, h[0], h[1], "HIGH", "-",  "-", "Known ftp credentials", creds)

def parse_enum_shares():

    for host in SMBlist:
        h = host.split(":")
        datos=leer_fich("SMB/enum_shares_" + h[0] + "_p" + h[1] + ".txt")
        guest_session = False
        list_shares = False
        accesible_shared = False
        shares = ""

        if datos!="":
            datos = datos.split("\n")  
            if len(datos) > 1:
                shares = "The following samba share have been listed:\n"
                for linea in datos:
                    if "[+] Guest session" in linea:
                        guest_session = True
                    elif "Disk" in linea:
                        list_shares = True
                        shares = shares + "\n"
                    elif "READ, WRITE" in linea or "READ" in linea or "READ ONLY" in linea or "WRITE" in linea or "r-" in linea:
                        accesible_shared = True
                        shares = shares + "\n"
                    elif "Working on it..." not in linea:
                        shares = shares + "\n"

                if guest_session and list_shares and accesible_shared == False:
                    aniadir_vuln(1, h[0], h[1], "LOW", "-",  "-", "Enumeration of Samba Shares without access", shares)
                elif guest_session and list_shares and accesible_shared:
                    aniadir_vuln(1, h[0], h[1], "HIGH", "-",  "-", "Enumeration of Samba Shares without access", shares)   


def parse_smb():
    
    for host in SMBlist:
        h = host.split(":")
        datos=leer_fich("SMB/data_smb_" + h[0] + "_p" + h[1] + ".txt")  
        
        if datos!="": 
            datos = datos.split("\n")
            credential = False
            characters = "'.\,"
            smb_creds = []
            version = ""

            for linea in datos:
                atrib = linea.split(" ")
                if "[32m[+]" in atrib[0]:
                    for i in atrib:
                        if i=="Success:":
                            credential =  True
                            break
                    if credential and len(atrib) == 7:
                        cred = atrib[6]
                        for x in range(len(characters)):
                            cred = cred.replace(characters[x],"")
                        smb_creds.append(cred)
                    elif credential == False:
                        atrib = linea.split("-") 
                        version = atrib[1]
            
            if len(smb_creds) > 0:
                creds = "The following valid credentials have been listed:"
                for i in smb_creds:
                    creds = creds + "\n" + i
                aniadir_vuln(1, h[0], h[1], "HIGH", "-",  "-", "Known samba credentials", creds)
            
            if version != "":
                aniadir_vuln(1, h[0], h[1], "LOW", "-",  "-", "Known samba version", version)
 

def parse_ssh_audit():
    for host in SSHlist:
        elliptic= ""
        cbc = ""
        mac = ""
        existe_ip = False
        pos_ip = 0
        vulnList = []
        portList = []
        dirList = []

        h = host.split(":")
        datos=leer_fich(dir_ssh + "_audit_" + h[0] + "_" + h[1] + ".xml")

        if datos!="":
            datos = datos.split("\n")

            for linea in datos:
                atrib = linea.split(" ")
                if atrib[0]=="\x1b[0;31m(kex)" or atrib[0]=="\x1b[0;33m(kex)":
                    elliptic = elliptic + atrib[1] + ", "
                elif atrib[0]=="\x1b[0;31m(key)" or atrib[0]=="\x1b[0;33m(key)":
                    cbc = cbc + atrib[1] + ", "
                elif atrib[0]=="\x1b[0;31m(mac)" or atrib[0]=="\x1b[0;33m(mac)":
                    mac = mac + atrib[1] + ", "

            if elliptic!="":                
                vuln = textTohtml.Vulnerabilidad(3, "LOW", h[1], "-", "-", "SSH weak algorithms elliptic curves", "Affected cipher suites: " + elliptic)
                vulnList.append(vuln)

            if cbc !="":
                vuln = textTohtml.Vulnerabilidad(3, "LOW", h[1], "-", "-", "SSH weak CBC algorithms", "Affected cipher suites: " + cbc)
                vulnList.append(vuln)

            if mac!="":
                vuln = textTohtml.Vulnerabilidad(3, "LOW", h[1], "-", "-", "SSH weak MAC algorithms", "Affected cipher suites: " + mac)
                vulnList.append(vuln)

            for iteration,item in enumerate(ipsList):
                if item.ip == h[0]:
                    existe_ip = True
                    pos_ip = iteration
                    break
            if existe_ip:
                ipsList[pos_ip].vulnerabilidades.extend(vulnList)
            else:
                data = textTohtml.Ip(h[0], vulnList, portList, dirList)
                ipsList.append(data)

def parse_ssh_enum():
    for host in SSHlist:
        vulnList = []
        portList = []
        dirList = []
        existe_ip = False
        descripcion = "-"
        count_valid_user = 0
        pos_ip = 0
        vuln = ""

        h = host.split(":")

        datos=leer_fich(dir_ssh + "_enum_" + h[0] + "_" + h[1] + ".txt")
        if datos!="":
            datos = datos.split("\n")
            if datos[0]!="Target host most probably is not vulnerable or already patched, exiting...":
                descripcion = "The following valid users have been listed: "
                for linea in datos:
                    if "is a valid user!" in linea:
                        l = linea.split(" ")
                        if count_valid_user == 0:
                            descripcion = descripcion + " " + l[0]
                        else:
                            descripcion = descripcion + ", " + l[0]
                        count_valid_user = count_valid_user + 1
                descripcion = descripcion + "."

                vuln = textTohtml.Vulnerabilidad(7, "HIGH", h[1], "CVE-2018-15473", "-", "OpenSSH < = 7.7 - User Enumeration", descripcion)
                vulnList.append(vuln)

            for iteration,item in enumerate(ipsList):
                if item.ip == h[0]:
                    existe_ip = True
                    pos_ip = iteration
                    break
            if existe_ip:
                ipsList[pos_ip].vulnerabilidades.extend(vulnList)
            else:
                data = textTohtml.Ip(h[0], vulnList , portList, dirList)
                ipsList.append(data)

        #Si queremos sacar los datos del sshUserEnum en json
        #if datos!="":
            #dt=json.loads(datos)
            #if len(dt['Valid'])>0:
                #print("hay enumeracion")

def parse_tls():

    for host in TLSlist:
        h = host.split(":")
        datos=leer_fich(dir_testssl + h[0] + "_p" + h[1] + ".json")
        if datos!="":
            dt=json.loads(datos)
            for severity in dt['scanResult']:
                vuelta = 0
                for i in severity['protocols']:
                    if i['severity'] == "CRITICAL" or i['severity'] == "HIGH" or i['severity'] == "MEDIUM" or i['severity'] == "LOW" or i['severity'] == "INFO":
                        aniadir_vuln(vuelta, h[0], h[1], i['severity'], "-", "-", "Offeres deprecated protocol " + str(i['id']), "-")
                    vuelta = vuelta +1
                #Si queremos guardar los cifrados
                #for i in severity['fs']:
                    #if i['severity'] == "CRITICAL" or i['severity'] == "HIGH" or i['severity'] == "MEDIUM" or i['severity'] == "LOW":
                        #d = str(i['finding'])
                        #print(d)
                        #d = d.split(" ")
                        #dat = host
                        #for item in d:
                            #if len(item)>0:
                                #dat = dat + ":" + item
                        #TLSciphers.append(dat)

                for i in severity['vulnerabilities']:
                    if i['severity'] == "CRITICAL" or i['severity'] == "HIGH" or i['severity'] == "MEDIUM" or i['severity'] == "LOW" or i['severity'] == "INFO":
                        if i['id'] == "secure_client_renego":
                            aniadir_vuln(vuelta, h[0], h[1], i['severity'], i["cve"], i["cwe"], "Secure client renegotiation", i["finding"])
                        elif i['id'] == "secure_renego":
                            aniadir_vuln(vuelta, h[0], h[1], i['severity'], "-", i["cwe"], "Secure renegotiation", i["finding"])
                        elif i['id'] == "heartbleed":
                            description = "An attacker can read 64 KB of information in the memory of the vulnerable service, and can access any critical information stored there, such as system credentials, tokens, certificates, etc."
                            aniadir_vuln(vuelta, h[0], h[1], i['severity'], i["cve"], i["cwe"], "Heartbleed vulnerability", description)
                        elif i['id'] == "CCS":
                            description = "This vulnerability allows malicious intermediate nodes to intercept encrypted data and decrypt them while forcing SSL clients to use weak keys which are exposed to the malicious nodes."
                            aniadir_vuln(vuelta, h[0], h[1], i['severity'], i["cve"], i["cwe"], "CCS Injection Vulnerability", description)
                        else:
                            if i["id"] != "fallback_SCSV":
                                aniadir_vuln(vuelta, h[0], h[1], i['severity'], i["cve"], i["cwe"], i["id"], i["finding"])
                    vuelta = vuelta +1

                for i in severity['headerResponse']:
                    if i['severity'] == "CRITICAL" or i['severity'] == "HIGH" or i['severity'] == "MEDIUM" or i['severity'] == "LOW":
                        if i['id'] == "HSTS":
                            aniadir_vuln(vuelta, h[0], h[1], "MEDIUM", "-", "CWE-693", "Missing security header HSTS", " Security header Strict-Transport-Security not offered.")
                        elif i['id'] == "security_headers" and str(i['finding']) == "--":
                            aniadir_vuln(vuelta, h[0], h[1], "INFO", "-", "CWE-693", "Missing security headers", "missing: X-FRAME-OPTIONS, X-XSS-SECURITY, Content Security Policy, Cache Control...")
                        else:
                            aniadir_vuln(vuelta, h[0], h[1], i['severity'], "-", "-", i["id"], i["finding"])

                    if i['severity'] == "INFO":
                        if i['id'] == "banner_server" and i['finding'] != "No Server banner line in header, interesting!":
                            aniadir_vuln(vuelta, h[0], h[1], "LOW", "-", "CWE-200", "Information Disclousure", "Server header exposed: " + i["finding"])
                        if i['id'] == "cookie_count" and i['finding'] == "0 at '/' (30x detected, better try target URL of 30x)":
                            aniadir_vuln(vuelta, h[0], h[1], "LOW", "-", "CWE-614", "Sentitive Cookie without 'Secure' Flag", "-")
                            aniadir_vuln(vuelta, h[0], h[1], "LOW", "-", "CWE-1004", "Sentitive Cookie without'HTTPOnly' Flag", "-")
                    vuelta = vuelta +1

                for i in severity['serverPreferences']:
                    if i['severity'] == "CRITICAL" or i['severity'] == "HIGH" or i['severity'] == "MEDIUM" or i['severity'] == "LOW":
                        if i['id'] == "FS":
                            aniadir_vuln(vuelta, h[0], h[1], "LOW", "-", "CWE-327", "SSL/TLS Forward Secrecy Cipher Suites Not Supported", i["finding"])
                    vuelta = vuelta + 1
                    
                for i in severity['serverDefaults']:
                    if i['severity'] == "CRITICAL" or i['severity'] == "HIGH" or i['severity'] == "MEDIUM" or i['severity'] == "LOW":
                        if i['id'] == "cert_chain_of_trust":
                            aniadir_vuln(vuelta, h[0], h[1], "LOW", "-", "CWE-327", "SSL/TLS Forward Secrecy Cipher Suites Not Supported", i["finding"])
                    if i['id'] == "cert_expirationStatus":
                        if "expired" in i['finding']:
                            aniadir_vuln(vuelta, h[0], h[1], "LOW", "-", "CWE-298", "Certificate expired", i["finding"])
                        else:
                            cad = i['finding'].split(" ")
                            if int(cad[0]) > 396:
                                aniadir_vuln(vuelta, h[0], h[1], "LOW", "-", "-", "Long Certificate Validity", i["finding"] + " --- More than 13 months is way too long")
                    vuelta = vuelta + 1

def aniadir_puerto(vuelta, ip, protocolo, puerto, servicio, producto, version, estado):
    portList = []
    vulnList = []
    dirList = []
    existe_ip = False
    existe_puerto = False
    pos_ip = 0
    port = ""

    if puerto != "-" and puerto != "":
        port = textTohtml.Ports(protocolo, puerto, servicio, producto, version, estado)
        portList.append(port)
        if vuelta > 0:
            for iteration,item in enumerate(ipsList):
                if item.ip == ip:
                    existe_ip = True
                    pos_ip = iteration
                    break
            if existe_ip:
                for item in ipsList:
                    for i in item.data_ports:
                        if i.protocol == protocolo and  i.port == puerto and item.ip == ip:
                            existe_puerto = True
                            break
                if not existe_puerto:     
                    ipsList[pos_ip].data_ports.extend(portList)
            else:
                data = textTohtml.Ip(ip, vulnList, portList, dirList)
                ipsList.append(data)
        else:
            for iteration,item in enumerate(ipsList):
                if item.ip == ip:
                    existe_ip = True
                    pos_ip = iteration
                    break
            if existe_ip:
                ipsList[pos_ip].data_ports.extend(portList)
            else:
                data = textTohtml.Ip(ip, vulnList, portList, dirList)
                ipsList.append(data)

def parse_http_methods():
    for host in HTTPlist:
        h = host.split(":")
        tree = ET.parse("WEB/METHODS_HTTP/nmap_http_methods_" + h[0] + "_p" + h[1] + ".xml")
        root = tree.getroot()

        for host in root.iter('host'):
            for ports in host.iter('ports'):
                for port in ports.iter('port'):
                    list_methods = ""
                    for state in port.iter('state'):
                        if state.attrib['state'] == "open":
                            for service in port.iter('service'):
                                if "http" in service.attrib['name']:
                                   for script in port.iter('script'):
                                       if "http-methods" in script.attrib['id']:
                                            methods = script.attrib['output']
                                            m = methods.split(" ")
                                            for i in m:    
                                                list_methods = "Supported Methods: " 
                                                if i != "&#xA;" and i != "Supported" and i != "Methods:" and i != "GET" and i != "HEAD" and i != "POST":
                                                    list_methods = list_methods + i + ", "
                    l = len("Supported Methods: ")
                    if list_methods != "Supported Methods: " and len(list_methods) != l and list_methods != "":
                        aniadir_vuln(1, h[0], h[1], "MEDIUM", "-",  "-", "Insecure HTTP methods supported", list_methods)

def nmap_parser(dir):
    tree = ET.parse(dir)
    root = tree.getroot()

    for host in root.iter('host'):
        IPaddr = '-'
        protocol='-'
        p='-'
        serv='-'
        prod='-'
        v='-'
        s='-'
        for address in host.iter('address'):
            vuelta = 0
            if "ipv4" in (address.attrib['addrtype']):
                IPaddr = (address.attrib['addr'])
                for ports in host.iter('ports'):
                    for port in ports.iter('port'):
                        for state in port.iter('state'):
                            if state.attrib['state'] == "open":
                                protocol = port.attrib['protocol']
                                p = port.attrib['portid']
                                s = state.attrib['state']
                                for service in port.iter('service'):
                                    atributos = service.attrib
                                    if "name" in atributos:
                                        serv = service.attrib['name']
                                    if "version" in atributos:
                                        v = service.attrib['version']
                                    if "product" in atributos:
                                        prod = service.attrib['product']
                                    if "tunnel" in atributos and serv!="https":
                                        serv = serv + "/" + service.attrib['tunnel']
                        aniadir_puerto (vuelta, IPaddr, protocol, p, serv, prod, v, s)
                        vuelta = vuelta + 1


def nmap_TCP_xml_parser():
    tree = ET.parse(dir_nmap_tcp)
    root = tree.getroot()

    IPaddr = ''

    for host in root.iter('host'):
        for address in host.iter('address'):
            if "ipv4" in (address.attrib['addrtype']):
                IPaddr = (address.attrib['addr'])
        for ports in host.iter('ports'):
            for port in ports.iter('port'):
                for state in port.iter('state'):
                    if state.attrib['state'] == "open":
                        for service in port.iter('service'):
                            if "ssh" in service.attrib['name']:
                                SSHlist.append(IPaddr + ":" + port.attrib['portid'])
                            elif ("tls" in service.attrib['name'] or "ssl" in service.attrib['name'] or "https" in service.attrib['name']):
                                TLSlist.append(IPaddr + ":" + port.attrib['portid'])
                            elif ("smb" in service.attrib['name'] or "netbios" in service.attrib['name'] or "microsoft-ds" in service.attrib['name']):
                                SMBlist.append(IPaddr+ ":" + port.attrib['portid'])
                            elif ("ftp" in service.attrib['name'] or "ftps" in service.attrib['name']):
                                FTPlist.append(IPaddr+ ":" + port.attrib['portid'])
                            elif ("telnet" in service.attrib['name']):
                                TLNTlist.append(IPaddr+ ":" + port.attrib['portid'])
                            elif ("http" in service.attrib['name']):
                                for service in port.iter('service'):
                                    atributos = service.attrib
                                    if "tunnel" in atributos:
                                        if "ssl" in service.attrib['tunnel']:
                                            TLSlist.append(IPaddr + ":" + port.attrib['portid'])
                                HTTPlist.append(IPaddr+ ":" + port.attrib['portid'])
                            else:
                                try:
                                    if "ssl" in service.attrib['tunnel']:
                                        TLSlist.append(IPaddr + ":" + port.attrib['portid'])
                                except KeyError:
                                    pass
    return SSHlist, TLSlist, SMBlist, FTPlist, TLNTlist, HTTPlist


def main():
    #se añaden para una prueba
    #modo_agresivo =  True
    #nmap_TCP_xml_parser()
    #print("\n ENTRAMOS EN MAIN PARSE\n")

    #para sacar los datos de los puertos
    nmap_parser(dir_nmap_tcp)
    nmap_parser(dir_nmap_udp)

    if len(SSHlist) > 0:
        parse_ssh_audit()
        parse_ssh_enum()

    if len(TLSlist) > 0:
        parse_tls()

    if len(SMBlist)>0:
        parse_enum_shares()
        parse_smb()

    if len(FTPlist)>0:
        parse_ftp()

    if len(TLNTlist)>0:
        parse_telnet()

    if len(HTTPlist) > 0:
        parse_http_methods()
        
    ordenar_ipsList()

    if len(HTTPlist) > 0 and modo_agresivo:
        parse_fuzzing()

    #Para imprimir la lista de vulnerabilidades ordenada
    #print("\n------------ SORTED LIST ------------")
    #imprimir_ipsList(ipsList_ordenada)

    nombreHtml1 = textTohtml.envuelveDatosEnHTML(ipsList_ordenada, modo_agresivo, HTTPlist)

    nombreHtml= htmlTopdf.envuelveDatosEnHTML(ipsList_ordenada, modo_agresivo, HTTPlist)

    htmlTopdf.ToPdf(nombreHtml)

    os.system("cp "+ nombreHtml1 + " " + nombreHtml)
    os.system("rm " + nombreHtml1)


if __name__ == "__main__":
    main()
