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
  - Descubrimiento de puertos TCP y UDP abiertos con nmap (dependiendo de si el análisis es ligero o agresivo se  realizará de una forma u otra).
  - Si las máquinas tienen puertos SSH abiertos se mira los cifrados débiles y si existe enumeración de usuarios.
  - Si las máquinas tienen puertos SSL abiertos se le realiza el testssl.
  - Si las máquinas tienen puertos SMB abiertos se realiza una enumeración de shares, intenta realizar la detección de la versión de samba y fuerza bruta en el login.
  - Si las máquinas tiene puertos FTP abiertos comprueba si existe sesión anónima, intenta realizar la detección de la versión de FTP y fuerza bruta en el login.
  - Si las máquinas tienen puertos TELNET abiertos intenta realizar la detección de la versión de FTP y fuerza bruta en el login.
  - Si las máquinas tienen puertos HTTP/HTTPS abiertos comprueba los métodos HTTP usados y si el análisis se realiza en modo agresivo se realiza fuzzing de directorios web.
  - Cuando la herramienta acaba de realizar todos los análisis, networkScan trata toda la información recopilada por las herramientas y saca un informe en HTML y en PDF con el resultado del análisis de cada IP escaneada. Este informe incluye un índice y por cada IP una tabla de recuento de vulnerabilidades, una tabla de visibilidad de cada máquina, es decir, una tabla en la que se vean los puertos TCP/UDP que están abiertos y con qué servicios, una tabla de vulnerabilidades ordenada por criticidad con código de colores (Los niveles de criticidad que se han establecido son (de más crítico a menos critico): 1) Critico (morado), 2) Alto (rojo), 3) Medio (naranja), 4) Bajo (verde) y 5) Info (azul)) y si se realiza un análisis agresivo tendrá una sección llamada "Directory listing" con el listado de directorios web encontrados en cada puerto.

Las herramientas que utiliza networkScan son: nmap, ssh-audit, exploit de 
enumeración de usuarios ssh, testssl, smbmap, metasploit y dirsearch.

La herramienta cuenta con dos modos de escaneo: modo liegro y modo agresivo. Podemos ver las características de cada modo en la sigueinte tabla:

| |Modo Ligero|Modo Agresivo|
|:----|:----|:----|
|Comprobaciones previas|Si|Si|
|Escaneo de puertos TCP|Escanea los 32500 puertos más comunes.|Escanea todos los puertos.|
|Escaneo de puertos UDP|Escanea los 50 puertos más comunes.|Escanea los 100 puertos más comunes.|
|Análisis SSH|Detección de cifrados vulnerables e intento de enumeración de  usuarios.|Detección de cifrados vulnerables e intento de enumeración de  usuarios.|
|Análisis SSL|Detección de vulnerabilidades relacionadas con SSL.|Detección de vulnerabilidades relacionadas con SSL.|
|Análisis SMB|Enumeración de shares, detección de versión de SMB y fuerza bruta en el login.|Enumeración de shares, detección de versión de SMB y fuerza bruta en el login.|
|Análisis FTP|Comprobación de existencia de sesión anónima, detección de versión de FTP y fuerza bruta en el login.|Comprobación de existencia de sesión anónima, detección de versión de FTP y fuerza bruta en el login.|
|Análisis TELNET|Detección de versión de TELNET y fuerza bruta en el login.|Detección de versión de TELNET y fuerza bruta en el login.|
|Análisis HTTP/HTTPS|Detección de métodos HTTP usados.|Detección de métodos HTTP usados y fuzzing de directorios web.|
|Consumo de ancho de banda*|Medio-Bajo|Alto|
|N.º de peticiones realizadas*|Medio-Bajo|Alto|
|Tiempo de escaneo*|Medio-Bajo|Alto|

(*) Estos valores varían en función del volumen de la red que se esté escaneando por lo que no se puede dar una cifra concreta.

## Prerequisitos:

- Disponible para distribuciones Linux.

- Es necesario tener instalado python3.
  
- Es necesario tener instalado "nmap":
  - sudo apt-get install nmap

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

- smbmap: https://github.com/ShawnDEvans/smbmap

- metasploit: https://www.metasploit.com/

- dirsearch: https://github.com/maurosoria/dirsearch

- css: https://www.lightningdesignsystem.com/resources/downloads/
