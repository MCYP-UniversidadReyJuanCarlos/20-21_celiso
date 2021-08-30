# Trabajo de Fin de Máster 20-21_clijosor

## Título --> networkScan: Herramienta de escaneos automáticos en redes corporativas

Autor/a: Celia Lijó Soria

Tutor/a: Marta Beltrán Pardo


## Herramienta: networkScan

networkScan es una herramienta para la realización de escaneos automáticos en redes 
corporativas que está implementada en python. Esta herramienta se realiza para facilitar y 
ayudar al usuario a la hora de analizar una red corporativa para tener una visión general del 
estado de la misma, ya que la propia red puede ser muy grande y si no se necesitaría emplear 
mucho tiempo en el análisis de la misma. Gracias a esta herramienta podremos centrarnos en 
explotar los aspectos de la red que la herramienta nos muestre que son más vulnerables.

Esta herramienta se puede lanzar a una máquina, varias máquinas, un rango de ips... y para 
realizar los escaneos se sirve de otras herramientas que están en bash y python.

De momento la herramienta realiza:

  - Se realiza una comprobación de directorios, módulos y herramientas que son necesarios para el uso de la herramienta.
  - Descubrimiento de puertos con nmap
  - Si las máquinas tienen puertos SSH abiertos se mira los cifrados débiles y si existe enumeración de usuarios.
  - Si las máquinas tienen puertos SSL abiertos se le realiza el testssl. 
  - Cuando la herramienta acaba de realizar todos los análisis, saca un informe en HTML con el resultado del análisis de cada IP y en PDF. Este informe incluye un índice y por cada IP una tabla de recuento de vulnerabilidades, una tabla de visibilidad de cada máquina, es decir, una tabla en la que se vean los puertos TCP/UDP que están abiertos y con qué servicios y una tabla de vulnerabilidades.

Las herramientas necesarias están en el repositorio. 

De momento las herramientas que utiliza networkScan son nmap, ssh-audit, exploit de 
enumeración de usuarios ssh, testssl…

Se tiene pensado mirar más servicios y analizarlos como SMB, FTP, TELNET, DNS, añadir en puertos SSL 
fuzzing de directorios...

Una vez acabada la herramienta se tiene pensado añadir dos opciones de intensidad en la 
herramienta, es decir, si se quiere realizar un escaneo suave o intenso.

Otro objetivo es que no salgan por consola los resultados de las herramientas que se van 
lanzando y en su lugar salgan trazas de texto o una barra de progreso. Esto esta todavía en
desarrollo.

## Prerequisitos:

- Es necesario tener instalado "wkhtmltopdf": 
  - sudo apt-get install wkhtmltopdf

- Es necesario  tener instalado “smbmap” en Linux, suele estar instalado pero conviene comprobarlo antes de lanzar networkScan y sino instalarlo: 
  - sudo apt-get install smbmap

- Es necesario tener instalado “metasploit” en Linux, suele estar instalado pero conviene comprobarlo antes de lanzar networkScan y sino instalarlo:
  - sudo apt-get update
  - sudo apt install curl
  - curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
  - ./msfinstall

- Instalar el archivo "requirements.txt": 
  - pip install -r requirements.txt

## Uso de la herramienta:

Formas de lanzar la herramienta:

- python3 networkscan.py [URI]
- python3 networkscan.py [options] [URI]
- python3 networkscan.py [options]

Formas de uso y opciones:

1)	python3 networkscan.py [URI], donde [URI] es:

  - [URI]:   ip | ip1-N | ip1,ip2,ip3,ip4,ip5,...   por defecto se lanza el modo ligero

2)	python3 networkscan.py [options] [URI]", donde [URI] es:

  - [URI]:  ip | ip1-N | ip1,ip2,ip3,ip4,ip5,...   

    y [options] es/son:

  - -l, --light:  Opción para lanzar el escaneo en modo ligero
  - -a, --aggressive:  Opción para lanzar el escaneo en modo agresivo

3)	python3 networkscan.py [options]", donde [options] debe ir siempre acompañado de un archivo de entrada o de un [URI] como el anterior, excepto la opción de ayuda:

  - -h, --help:  Opción de ayuda, lo que se está viendo ahora.
  - -i, --input-file [file]:  El campo [URI] se introduce a través de un fichero de texto. Este archivo contiene la IP, IPs o rango de IPs a analizar.
  - -l, --light:  Opción para lanzar el escaneo en modo ligero
  - -a, --aggressive:  Opción para lanzar el escaneo en modo agresivo

   
 ## Notas:
 
  - El exploit sshUsernameEnumeration.py funciona con python3, a pesar de tener instalado el módulo de paramiko y en la version que es debida, debido a problemas que existian con el exploit hay que tener en cuenta estos cambios: https://github.com/agentgoblin/CVE-2018-15473-Exploit/commit/93607da515ead436d64958cdc9962081e62482e0 

  - ssh-audit también funciona con python3.

## Bibliografía:

- nmap: https://nmap.org/

- ssh-audit: https://github.com/arthepsy/ssh-audit

- Enumeración de usuarios ssh: https://github.com/Rhynorater/CVE-2018-15473-Exploit
    - Nota: Hay que hacer esta modificación --> https://github.com/agentgoblin/CVE-2018-15473-Exploit/commit/93607da515ead436d64958cdc9962081e62482e0

- testssl: https://github.com/drwetter/testssl.sh

- metasploit: https://www.metasploit.com/

- smbmap: https://github.com/ShawnDEvans/smbmap

- css: https://www.lightningdesignsystem.com/resources/downloads/
