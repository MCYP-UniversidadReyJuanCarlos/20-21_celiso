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

  - Descubrimiento de puertos con nmap
  - Si las máquinas tienen puertos SSH abiertos se mira los cifrados débiles y si existe enumeración de usuarios.
  - Si las máquinas tienen puertos SSL abiertos se le realiza el testssl. 
  - Cuando la herramienta acaba de realizar todos los análisis, saca un informe en HTML con el resultado del análisis de cada IP.

Las herramientas necesarias están en el repositorio. Aun así más adelante se tiene pensado 
comprobar desde networkScan si se tienen todos los módulos de python instalados, 
herramientas, etc.

De momento las herramientas que utiliza networkScan son nmap, ssh-audit, exploit de 
enumeración de usuarios ssh, testssl…

Se tiene pensado mirar más servicios y analizarlos como SMB, FTP, añadir en puertos SSL 
fuzzing de directorios...

Una vez acabada la herramienta se tiene pensado añadir dos opciones de intensidad en la 
herramienta, es decir, si se quiere realizar un escaneo suave o intenso.

Otro objetivo es que no salgan por consola los resultados de las herramientas que se van 
lanzando y en su lugar salgan trazas de texto o una barra de progreso. Esto esta todavía en
desarrollo.

También se tiene pensado añadir una tabla de visibilidad de cada máquina, es decir, una tabla 
en la que se vean los puertos TCP/UDP que están abiertos y con qué servicios.

Por último se quiere añadir comprobaciones de que todas las herramientas o módulos de 
python necesarios están en su sitio o instalados

## Prerequisitos:

- Es necesario tener instalado "wkhtmltopdf": sudo apt-get install wkhtmltopdf
- Instalar el archivo "requirements.txt": pip install -r requirements.txt

## Uso de la herramienta:

  1) python networkScan.py ip1
  2) python networkScan.py ip1,ip2,ip3,ip4,ip5,...,ipN
  3) python networkScan.py <rango_ips>
  4) python networkScan.py -i <fichero_hosts>
 
 *Ejemplo de <rango_ips>:*  192.1.130.1-129
 
 ## Notas:
 
  - El exploit sshUsernameEnumeration.py funciona con python3, a pesar de tener instalado el módulo de paramiko y en la version que es debida, debido a problemas que existian con el exploit hay que tener en cuenta estos cambios: https://github.com/agentgoblin/CVE-2018-15473-Exploit/commit/93607da515ead436d64958cdc9962081e62482e0 

  - ssh-audit también funciona con python3.

## Bibliografía:

- nmap: https://nmap.org/

- ssh-audit: https://github.com/arthepsy/ssh-audit

- Enumeración de usuarios ssh: https://github.com/Rhynorater/CVE-2018-15473-Exploit
    - Nota: Hay que hacer esta modificación --> https://github.com/agentgoblin/CVE-2018-15473-Exploit/commit/93607da515ead436d64958cdc9962081e62482e0

- testssl: https://github.com/drwetter/testssl.sh

- css: https://www.lightningdesignsystem.com/resources/downloads/




