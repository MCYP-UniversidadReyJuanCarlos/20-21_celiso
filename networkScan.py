#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
#Nombre: Celia Lijo Soria
import os, sys, json
from optparse import OptionParser
import xml.etree.ElementTree as ET
import warnings
import parse

warnings.filterwarnings("ignore")

#variables globales
dir_nmap_tcp = "NMAP/nmap_TCP_full.xml"
dir_nmap_udp = "NMAP/nmap_UDP_top-50.xml"
dir_ssh = "Herramientas/ssh"
dir_data_ssh = "SSH/ssh_"
dir_testssl = "Herramientas/testssl/testssl.sh"
dir_data_testssl = "WEB/TLS/testssl_"
dir_dirsearch = "Herramientas/dirsearch-master/dirsearch.py"
dir_data_dirsearch = "WEB/FUZZING/"
dir_data_methods_http = "WEB/METHODS_HTTP/"
dir_users = "Herramientas/ssh/userList.txt"
dir_users_telnet = "Herramientas/user_list_telnet.txt"
dir_data_ftp = "FTP/data_ftp_"

version = []
users = []

usage =  """\n\n"python3 networkscan.py <URI>"    or    "python3 networkscan.py [options] <URI>"    or    "python3 networkscan.py <options>"

Ways of usage:

1) python3 networkscan.py <URI>", where <URI> is:

     <URI>                         ip | ip1-N | ip1,ip2,ip3,ip4,ip5,...   a light scan is performed by default

2) python3 networkscan.py [options] <URI>", where <URI> is:

     <URI>                         ip | ip1-N | ip1,ip2,ip3,ip4,ip5,...   

and [options] is/are:

     -l, --light                   Option to launch the scan in light mode
     -a, --aggressive               Option to launch the scan in aggressive mode

3) python3 networkscan.py [options]", where [options] must always be accompanied by an input file or an <URI> as above, except for the help option:

     -h, --help                    what you're looking at
     -i, --input-file <file>       The <URI> field is entered via a text file. This file contains the ip, ips or range of ips to be analysed.
     -l, --light                   Option to launch the scan in light mode
     -a, -aggressive               Option to launch the scan in aggressive mode"""


def metodos_http(HTTPlist):
    print("\n-------------  HTTP METHODS -------------\n")
    for host in HTTPlist:
        h = host.split(":")
        os.system("nmap -sS -p " + h[1] +" --script http-methods "+ h[0] + " -oX " + dir_data_methods_http + "nmap_http_methods_" + h[0] + "_p" + h[1] + ".xml")

def fuzzing(HTTPlist):
    print("\n-------------  FUZZING DE DIRECTORIOS -------------\n")
    for host in HTTPlist:
        h = host.split(":")
        os.system(dir_dirsearch + " -u "+ host + " -e asp,aspx,html,php,txt,jpg,png,old,bak,zip,json,xml,xls,csv,tsv -w Herramientas/Seclists-master/Discovery/Web-Content/common.txt -t 10 -f -b -x 400,401,404,403,406,405,500 --format json -o " + dir_data_dirsearch + "dirsearch_" + h[0] + "_p" + h[1]+ ".json")

def telnet(TLNTlist):
    print("\n-------------  TELNET -------------\n")
    for host in TLNTlist:
        h = host.split(":")
        os.system("msfconsole -x 'use auxiliary/scanner/telnet/telnet_version; set RHOSTS " + h[0] + "; run; use auxiliary/scanner/telnet/telnet_login; set RHOSTS " + h[0] + "; set USER_FILE " + dir_users_telnet + "; set PASS_FILE " + dir_users_telnet + "; run; exit' > data_telnet_" + h[0] + "_p" + h[1] + ".txt")
        os.system("cat data_telnet_" + h[0] + "_p" + h[1] + ".txt | grep '32m' > TELNET/data_telnet_" + h[0] + "_p" + h[1] + ".txt")
        os.system("rm data_telnet_" + h[0] + "_p" + h[1] + ".txt")

def ftp(FTPlist):
    print("\n-------------  FTP -------------\n")
    for host in FTPlist:
        h = host.split(":")
        os.system("msfconsole -x ' use auxiliary/scanner/ftp/anonymous; set RHOSTS " + h[0] + "; run; use auxiliary/scanner/ftp/ftp_version; set RHOSTS " + h[0] + "; run; use auxiliary/scanner/ftp/ftp_login; set RHOSTS " + h[0] + "; set USER_FILE " + dir_users + "; set PASS_FILE " + dir_users + "; run; exit' > data_ftp_" + h[0] + "_p" + h[1] + ".txt")
        os.system("cat data_ftp_" + h[0] + "_p" + h[1] + ".txt | grep '32m' > " + dir_data_ftp + h[0] + "_p" + h[1] + ".txt")
        os.system("rm data_ftp_" + h[0] + "_p" + h[1] + ".txt")

def smb(SMBlist):
    print("\n-------------  SMB -------------\n")
    for host in SMBlist:
        h = host.split(":")
        os.system("smbmap -H  " + h[0] + " -R > SMB/enum_shares_" + h[0] + "_p" + h[1] + ".txt")
        os.system("msfconsole -x 'use auxiliary/scanner/smb/smb_version; set RHOSTS " + h[0] + "; run; exit' > data_smb_" + h[0] + "_p" + h[1] +  ".txt")
        os.system("msfconsole -x 'use auxiliary/scanner/smb/smb_login; set RHOSTS " + h[0] + "; set USER_FILE " + dir_users + "; set PASS_FILE " + dir_users + "; run; exit' >> data_smb_" + h[0] + "_p" + h[1] +  ".txt")
        os.system("cat data_smb_" + h[0] + "_p" + h[1] +  ".txt | grep '32m' > SMB/data_smb_" + h[0] + "_p" + h[1] +  ".txt")
        os.system("rm data_smb_" + h[0] + "_p" + h[1] + ".txt")

def testssl(TLSlist):
    print("\n-------------  TESTSSL -------------\n")
    
    for host in TLSlist:
        data = host.split(":")
        os.system(dir_testssl + " --json-pretty "+ host)
        os.system("mv " +data[0] +"_p" +data[1] +"* "+ dir_data_testssl + data[0] +"_p" + data[1] +".json")

def ssh_audit(SSHlist):
    print("\n-------------  SSH-AUDIT -------------\n")
    software = 0
    for host in SSHlist:
        host = host.split(":")
        os.system("python3 " + dir_ssh + "/ssh-audit/ssh-audit.py " + host[0] +" -p " + host[1] + " > " + dir_data_ssh + "audit_" + host[0] + "_" + host[1]+ ".xml")
        datos=leer_fich(dir_data_ssh +  "audit_" + host[0] + "_" + host[1] + ".xml")     
        datos = datos.split("\n")

        if len(datos) > 2:
            for linea in datos:
                atrib = linea.split(" ")
                if len(atrib) > 1:
                    if atrib[1]=="software:":
                        software=atrib[3]
                        break

            if type(software) != int: #si es un str, es decir, existe un valor
                array=software.split("p")
                version.append(array[0])
        else:
            version.append("0")

def ssh_enum(SSHlist):
    print("\n-------------  SSH-ENUM -------------\n")
    j=0
    datos = []
    for s in SSHlist:
        datos.append(s.split(":"))

    for i in version:
        i=float(i)
        if i<7.8:
            os.system("python3 " +dir_ssh + "/sshUsernameEnumExploit.py " + datos[j][0] +" --port "+ datos[j][1] + " --userList " + dir_users + " > " + dir_data_ssh + "enum_"+ datos[j][0] +"_"+ datos[j][1] +".txt")
        elif i==0.0:
            print("No se ha podido evaluar la enumeracion de usuarios por ssh en la maquina " + datos[j][0] + " en el puerto " + datos[j][1])
        else:
            print("La version de ssh " + str(i) +" de la maquina " + datos[j][0] + " en el puerto " + datos[j][1] + " no es vulnerable a enumeracion de usuarios. ")
        j=j+1

def crea_fich(name_fich, list):
    with open (name_fich, 'w') as f:
        for line in list:
            f.write("%s\n" % line)


def nmap(hosts, modo_agresivo):
    if modo_agresivo:
        print("\n-------------  NMAP TCP -------------\n")
        os.system("nmap -A -T5 -Pn --min-rate 10000 -p- " + hosts +" -oX " + dir_nmap_tcp)
        print("\n-------------  NMAP UDP -------------\n")
        os.system("nmap -sU -sV -Pn -T5 --min-rate 10000 --top-ports 1500 " + hosts +" -oX " + dir_nmap_udp)
    else:
        print("\n-------------  NMAP TCP -------------\n")
        os.system("nmap -A -T5 -Pn --min-rate 20000 --top-ports 32500 " + hosts +" -oX " + dir_nmap_tcp)
        print("\n-------------  NMAP UDP -------------\n")
        os.system("nmap -sU -T5 -Pn --min-rate 20000 --top-ports 50 " + hosts +" -oX " + dir_nmap_udp)

def hosts(datos):
    if "," in datos:
        h = datos.split(",")
        j=0
        for i in h:
            if j==0:
                ips = i 
            else:
                ips = ips + " " + i
            j = j +1
    elif "\n" in datos:
        h = datos.split("\n")
        j=0
        for i in h:
            if j==0:
                ips = i 
            else:
                ips = ips + " " + i
            j = j +1
    else: #si contiene espacios o "-"
        ips = datos

    text = "\n* The following IPs will be analysed: *\n"
    ip = ips.split(" ")
    for i in ip:
        text = text + "\n\t- " + i
    print(text)
    return ips

def quitar_ultimo_elemento(datos):
    longitud=len(datos)
    ultimaLetra=datos[longitud-1]
    if ultimaLetra=="\n" or ultimaLetra=="\t" or ultimaLetra==" ":
        new_datos=datos[:-1]
    else:
        new_datos=datos
    return new_datos

def leer_fich(fich):
    f = open(fich)
    datos = f.read()
    f.close()
    return datos

def usuarios():
    u = leer_fich(dir_users)
    users = u.split("\n")
    print(users)


def comprobar_herramientas():

    excepcion = False

    print("\nChecking for the necessary tools are present...\n")

    if not os.path.isfile(dir_ssh + "/ssh-audit/ssh-audit.py"):
        print("\t- There is no ssh-audit.py tool in: " + dir_ssh + "/ssh-audit/ssh-audit.py")
        excepcion = True
    if not os.path.isfile(dir_ssh + "/sshUsernameEnumExploit.py"):
        print("\t- There is no sshUsernameEnumExploit.py tool in: " + dir_ssh + "/sshUsernameEnumExploit.py")
        excepcion = True
    if not os.path.isfile(dir_users):
        print("\t- There is no list of common users in: " + dir_users)
        excepcion = True
    if not os.path.isfile("Herramientas/HTML/salesforce-lightning-design-system.min.css"):
        print("\t- There is no stylesheet salesforce-lightning-design-system.min.css: Herramientas/HTML/salesforce-lightning-design-system.min.css")
        excepcion = True
    if not os.path.isfile("parse.py"):
        print("\t- The parse.py module does not exist.")
        excepcion = True
    if not os.path.isfile("textTohtml.py"):
        print("\t- The textTohtml.py module does not exist.")
        excepcion = True
    if not os.path.isfile("htmlTopdf.py"):
        print("\t- The htmlTopdf.py module does not exist.")
        excepcion = True

    if excepcion:
        raise Exception()

def comprobar_directorios(modo_agresivo):
    print("\nChecking for the necessary directories...\n")

    if not os.path.isdir("NMAP"):
        print('\t- NMAP folder is created.')
        os.mkdir("NMAP")

    if not os.path.isdir("SSH"):
        print('\t- SSH folder is created.')
        os.mkdir("SSH")

    if not os.path.isdir("WEB"):
        print('\t- WEB folder is created.')
        os.mkdir("WEB")

    if not os.path.isdir("WEB/TLS"):
        print('\t- WEB/TLS folder is created.')
        os.mkdir("WEB/TLS")

    if not os.path.isdir("WEB/METHODS_HTTP"):
        print('\t- WEB/METHODS_HTTP folder is created.')
        os.mkdir("WEB/METHODS_HTTP")

    if not os.path.isdir("SMB"):
        print('\t- SMB folder is created.')
        os.mkdir("SMB")

    if not os.path.isdir("FTP"):
        print('\t- FTP folder is created.')
        os.mkdir("FTP")

    if not os.path.isdir("TELNET"):
        print('\t- TELNET folder is created.')
        os.mkdir("TELNET")

    if modo_agresivo:
        if not os.path.isdir("WEB/FUZZING"):
            print('\t- WEB/FUZZING folder is created.')
            os.mkdir("WEB/FUZZING")

def operaciones(ips, modo_agresivo):
    SSHlist = []
    TLSlist = []
    SMBlist = []
    FTPlist = []
    TLNTlist = []
    HTTPlist = []

    parse.modo_agresivo = modo_agresivo

    nmap(ips, modo_agresivo)

    SSHlist, TLSlist, SMBlist, FTPlist, TLNTlist, HTTPlist = parse.nmap_TCP_xml_parser()
    
    if len(SSHlist)>0:
        ssh_audit(SSHlist)
        ssh_enum(SSHlist)
        
    if len(TLSlist)>0:
        testssl(TLSlist)

    if len(SMBlist)>0:
        smb(SMBlist)
    
    if len(FTPlist)>0:
        ftp(FTPlist)
   
    if len(TLNTlist)>0:
        telnet(TLNTlist)

    if len(HTTPlist) > 0:
        if  modo_agresivo:
            fuzzing(HTTPlist)
        metodos_http(HTTPlist)

    parse.main()

def main():

    argumentos = sys.argv[1:]
    parser = OptionParser(usage)

    parser.add_option("-i","--input-file",
    			action="store_true", dest="inputFile",
    			help="Input File")

    parser.add_option("-a","--aggressive",
            action="store_true", dest="aggressive",
            help="Aggressive")

    parser.add_option("-l","--light",
        action="store_true", dest="light",
        help="Light")

    (opciones, argumentos) = parser.parse_args()

    try:
        if len(argumentos) == 0 or len(argumentos)>1:
    	    raise Exception("\n*** [Error] --> Badly introduced arguments ***\n\nUsage: " + usage)
        else:
            comprobar_herramientas()
            comprobar_directorios(opciones.aggressive)
            #usuarios()

        if opciones.inputFile and os.path.isfile(argumentos[0]):
            print("\nInput file option active...\n")
            datos = leer_fich(argumentos[0])
            datos = quitar_ultimo_elemento(datos)
            ips=hosts(datos)    
        elif opciones.inputFile and os.path.isfile(argumentos[0]) == False:
            raise Exception("\n*** [Error] --> Badly introduced arguments ***\n\nUsage: " + usage)
        else:
            print("\nURI is entered...\n")
            ips=hosts(argumentos[0])  
  
        if opciones.light and opciones.aggressive:
            raise Exception("\n*** [Error] --> Badly introduced arguments ***\n\nUsage: " + usage)
        elif opciones.aggressive:
            print("\nLaunching the scan in aggressive mode...\n")
            operaciones(ips, True)
        elif opciones.light:
            print("\nLaunching the scan in light mode...\n")
            operaciones(ips, False)
        else:
            print("\nLaunching the scan... By default it uses the light mode...\n")
            operaciones(ips, False)

    except Exception as e:
        print (e)

if __name__ == "__main__":
    main()
