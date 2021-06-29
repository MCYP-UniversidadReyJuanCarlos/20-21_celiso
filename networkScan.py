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


def testssl():
    print("\n-------------  TESTSSL -------------\n")
    
    for host in TLSlist:
        print(host)
        data = host.split(":")
        print(data)
        os.system(dir_testssl + " --json-pretty "+host)
        os.system("mv " +data[0] +"_p" +data[1] +"* "+ dir_data_testssl + data[0] +"_p" + data[1] +".json")

def ssh_audit():
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

def ssh_enum():
    print("\n-------------  SSH-ENUM -------------\n")
    j=0
    datos = []
    for s in SSHlist:
        datos.append(s.split(":"))

    for i in version:
        i=float(i)
        if i>2.1 and i<7.8:
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

    print("\nSe van a analizar los siguientes datos: ")
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

#falta por desarrollar
def comprobar_herramientas():
    print("comprobando si están las herramientas necesarias...")

#falta por desarrollar
def comprobar_modulos():
    print("comprobando si están los modulos necesarios...")

def comprobar_directorios():
    print("comprobando si están los directorios necesarios...")

    if not os.path.isdir("NMAP"):
        print('Se crea la carpeta NMAP que no existe.')
        os.mkdir("NMAP")

    if not os.path.isdir("SSH"):
        print('Se crea la carpeta SSH que no existe.')
        os.mkdir("SSH")

    if not os.path.isdir("TLS"):
        print('Se crea la carpeta TLS que no existe.')
        os.mkdir("TLS")

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
    usage = "\n\t1) %prog ip1,ip2,ip3,ip4,ip5,...,ipN\t or \t %prog <range_ips>\n\t2) %prog -i hosts.txt"
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
            comprobar_herramientas()
            comprobar_modulos()
            comprobar_directorios()

        if opciones.inputFile and os.path.isfile(argumentos[0]):
            datos = leer_fich(argumentos[0])
            datos = quitar_ultimo_elemento(datos)
            ips=hosts(datos)
            operaciones(ips)
            nmap(ips)
        elif opciones.inputFile and os.path.isfile(argumentos[0])==false:
            raise Exception("Argumentos mal introducidos\nUsage: " + usage)
        else:
            ips=hosts(argumentos[0])  
            operaciones(ips)          

    except Exception as e:
        print (e)

if __name__ == "__main__":
    main()