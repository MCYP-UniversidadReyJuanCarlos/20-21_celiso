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
dir_data_testssl = "TLS/testssl_"
version = []

#En desarrollo
def ftp(FTPlist):
    print("\n-------------  FTP MAP -------------\n")
    #for host in FTPlist:
    #    os.system(dir_ftp + " " + host[0] +":"+host[1]+".json "+host[0]+":"+host[1])

#En desarrollo
def smb(SMBlist):
    print("\n-------------  SMB MAP -------------\n")
    #for host in SMBlist:
    #    os.system(dir_smb + " " + host[0] +":"+host[1]+".json "+host[0]+":"+host[1])

def testssl(TLSlist):
    print("\n-------------  TESTSSL -------------\n")
    
    for host in TLSlist:
        data = host.split(":")
        os.system(dir_testssl + " --json-pretty "+host)
        os.system("mv " +data[0] +"_p" +data[1] +"* "+ dir_data_testssl + data[0] +"_p" + data[1] +".json")

def ssh_audit(SSHlist):
    print("\n-------------  SSH-AUDIT -------------\n")

    for host in SSHlist:
        host = host.split(":")
        os.system("python3 " + dir_ssh + "/ssh-audit/ssh-audit.py " + host[0] +" -p " + host[1] + " > " + dir_data_ssh + "audit_" + host[0] + "_" + host[1]+".xml")
        datos=leer_fich(dir_data_ssh +  "audit_" + host[0] + "_" + host[1] + ".xml")     
        datos = datos.split("\n")

        if len(datos) > 2:
            for linea in datos:
                atrib = linea.split(" ")
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
            os.system("python3 " +dir_ssh + "/sshUsernameEnumExploit.py " + datos[j][0] +" --port "+ datos[j][1] + " --userList " + dir_ssh + "/userList.txt > " + dir_data_ssh + "enum_"+ datos[j][0] +"_"+ datos[j][1] +".txt")
        elif i==0.0:
            print("No se ha podido evaluar la enumeracion de usuarios por ssh en la maquina " + datos[j][0] + " en el puerto " + datos[j][1])
        else:
            print("La version de ssh " + str(i) +" de la maquina " + datos[j][0] + " en el puerto " + datos[j][1] + " no es vulnerable a enumeracion de usuarios. ")
        j=j+1

def crea_fich(name_fich, list):
    with open (name_fich, 'w') as f:
        for line in list:
            f.write("%s\n" % line)

def nmap(hosts):
    print("\n-------------  NMAP TCP -------------\n")
    os.system("nmap -A -T5 --min-rate 20000 --top-ports 15000 " + hosts +" -oX " + dir_nmap_tcp)
    print("\n-------------  NMAP UDP -------------\n")
    os.system("nmap -sU -sV -T5 --min-rate 20000 --top-ports 50 " + hosts +" -oX " + dir_nmap_udp)

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

    print("\nSe van a analizar los siguientes ips: ")
    ip = ips.split(" ")
    for i in ip:
        print(i)
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

#En desarrollo
def comprobar_herramientas():
    print("comprobando si están las herramientas necesarias...")

    if not os.path.isfile(dir_ssh + "/ssh-audit/ssh-audit.py"):
        raise Exception("No existe la herramienta ssh-audit.py en: ./" + dir_ssh + "/ssh-audit/ssh-audit.py")
    if not os.path.isfile(dir_ssh + "/sshUsernameEnumExploit.py"):
        raise Exception("No existe la herramienta sshUsernameEnumExploit.py en: ./" + dir_ssh + "/sshUsernameEnumExploit.py")
    if not os.path.isfile(dir_ssh + "/userList.txt"):
        raise Exception("No existe el listado de usuarios comunes en: ./" + dir_ssh + "/userList.txt")
    if not os.path.isfile("Herramientas/HTML/salesforce-lightning-design-system.min.css"):
        raise Exception("No existe la hoja de estilo salesforce-lightning-design-system.min.css: ./Herramientas/HTML/salesforce-lightning-design-system.min.css")
    if not os.path.isfile("parse.py"):
        raise Exception("No existe el módulo parse.py")
    if not os.path.isfile("textTohtml.py"):
        raise Exception("No existe el módulo textTohtml.py")
    if not os.path.isfile("htmlTopdf.py"):
        raise Exception("No existe el módulo htmlTopdf.py")

#En desarrollo
def comprobar_modulos():
    print("comprobando si están los modulos necesarios...")
    #pip list | grep pdfkit
    #echo $? --> este comando da cero si el anterior existe, es decir, está instalado y sino da 1

def comprobar_directorios():
    print("comprobando si están los directorios necesarios...")

    if not os.path.isdir("NMAP"):
        print('Se crea la carpeta NMAP.')
        os.mkdir("NMAP")

    if not os.path.isdir("SSH"):
        print('Se crea la carpeta SSH.')
        os.mkdir("SSH")

    if not os.path.isdir("TLS"):
        print('Se crea la carpeta TLS.')
        os.mkdir("TLS")

    #if not os.path.isdir("SMB"):
        #print('Se crea la carpeta SMB.')
        #os.mkdir("SMB")

def operaciones(ips):
    SSHlist = []
    TLSlist = []
    SMBlist = []

    nmap(ips)
    SSHlist, TLSlist, SMBlist = parse.nmap_TCP_xml_parser()
    
    
    if len(SSHlist)>0:
        ssh_audit(SSHlist)
        ssh_enum(SSHlist)
        
    if len(TLSlist)>0:
        testssl(TLSlist)

    parse.main()

def main():
    usage = "\n\t1)%prog ip1,ip2,ip3,ip4,ip5,...,ipN\n\t2)%prog -i hosts.txt"
    argumentos = sys.argv[1:]
    parser = OptionParser(usage)

    parser.add_option("-i","--input-file",
    			action="store_true", dest="inputFile",
    			help="Input File")

    (opciones, argumentos) = parser.parse_args()

    try:
        if len(argumentos) == 0 or len(argumentos)>1:
    	    raise Exception("Argumentos mal introducidos\nUsage: " + usage)
        else:
            #En desarollo
            #comprobar_modulos()
            comprobar_herramientas()
            comprobar_directorios()

        if opciones.inputFile and os.path.isfile(argumentos[0]):
            datos = leer_fich(argumentos[0])
            datos = quitar_ultimo_elemento(datos)
            ips=hosts(datos)
            operaciones(ips)
        elif opciones.inputFile and os.path.isfile(argumentos[0]) == False:
            raise Exception("Argumentos mal introducidos\nUsage: " + usage)
        else:
            ips=hosts(argumentos[0])  
            operaciones(ips)          

    except Exception as e:
        print (e)

if __name__ == "__main__":
    main()
