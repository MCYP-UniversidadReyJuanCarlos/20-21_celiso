#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
#Nombre: Celia Lijo Soria
import os, sys, json
from optparse import OptionParser
import xml.etree.ElementTree as ET
import warnings
import textTohtml

warnings.filterwarnings("ignore")


dir_nmap_tcp = "NMAP/nmap_TCP_full.xml"
dir_data_ssh = "SSH/ssh"
dir_testssl = "TLS/testssl_"

ipsList = []
ipsList_ordenada = []

SSHlist = []
TLSlist = []
SMBlist = []

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

    data = textTohtml.Ip(lista.ip, vulnList)
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
        print("\n")
        print(elem.ip)
        for vul in elem.vulnerabilidades:
            num_vulns = num_vulns + 1
            print(str(num_vulns) + ". " + vul.titulo + " " + vul.descripcion)
            
        num_ips = num_ips + 1
    print("Hay "+ str(num_ips) + " con " + str(num_vulns) + " vulnerabilidades")

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
            data = textTohtml.Ip(ip, vulnList)
            ipsList.append(data)
    elif vuln != "":
        data = textTohtml.Ip(ip, vulnList)
        ipsList.append(data)

def parse_ssh_audit():
    for host in SSHlist:
        elliptic= ""
        cbc = ""
        mac = ""
        existe_ip = False
        pos_ip = 0
        vulnList = []

        h = host.split(":")
        datos=leer_fich(dir_data_ssh + "_audit_" + h[0] + "_" + h[1] + ".xml")

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
                data = textTohtml.Ip(h[0], vulnList)
                ipsList.append(data)

def parse_ssh_enum():
    for host in SSHlist:
        vulnList = []
        existe_ip = False
        descripcion = "-"
        count_valid_user = 0
        pos_ip = 0
        vuln = ""

        h = host.split(":")

        datos=leer_fich(dir_data_ssh + "_enum_" + h[0] + "_" + h[1] + ".txt")
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
                data = textTohtml.Ip(h[0], vulnList)
                ipsList.append(data)

        #Si queremos sacar los datos del sshUserEnum en json
        #if datos!="":
            #dt=json.loads(datos)
            #if len(dt['Valid'])>0:
                #print("hay enumeracion")

def parse_tls():
    data = []
    da = []
    pos_ip = 0
    vuln = ""
    cvss = 0

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
                        else:
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
                            elif ("smb" in service.attrib['name'] or "netbios" in service.attrib['name']):
                                SMBlist.append(IPaddr)
                            else:
                                try:
                                    if "ssl" in service.attrib['tunnel']:
                                        TLSlist.append(IPaddr + ":" + port.attrib['portid'])
                                except KeyError:
                                    pass
    return SSHlist, TLSlist, SMBlist

def main():
  
    if len(SSHlist)>0:
        parse_ssh_audit()
        parse_ssh_enum()
    if len(TLSlist)>0:
        parse_tls()

    #Para imprimir la lista de vulnerabilidades
    #print("LISTA SIN ORDENAR:")
    #imprimir_ipsList(ipsList)
    ordenar_ipsList()
    #Para imprimir la lista de vulnerabilidades ordenada
    #print("\nLISTA ORDENADA:")
    #imprimir_ipsList(ipsList_ordenada)

    textTohtml.envuelveDatosEnHTML(ipsList_ordenada)
    

if __name__ == "__main__":
    main()
