# TFM 20-21_clijosor: 

## Titulo: Diseño y desarrollo de herramientas que automaticen la explotación de vulnerabilidades/auditoría

## Herramienta: networkScan

Esta herramienta se puede lanzar a una máquina, varias máquinas, un rango de ips... y está programada en python 2, aunque utiliza herramientas que están en python 3.

De momento la herramienta realiza:

  - Descubrimiento de puertos con nmap
  - Si las máquinas tienen puertos SSH abiertos se mira los cifrados débiles y si existe enumeración de usuarios.
  - Si las máquinas tienen puertos SSL abiertos se le realiza el testssl. Cuando la herramienta acaba de realizar todos los análisis.
  - Saca un informe en HTML con el resultado del análisis de cada IP.

Las herramientas necesarias están en el repositorio. Aún así más adelante se tiene pensado comprobar desde networkScan si se tienen todos los modulos de python instalados, herramientas, etc.

Se tiene pensado mirar más servicios y analizarlos como SMB, FTP, añadir en puertos SSL fuzzing de directorios...

Una vez acabada la herramienta se tiene pensado añadir dos opciones de intensidad en la herramienta, es decir, si se quiere realizar un escaneo suave o intenso.

Otro objetivo es que no salgan por consola los resultados de las herramientas que se van lanzando y en su lugar salgan trazas de texto o una barra de progreso. Esto esta todavia en desarrollo.

## Usage

  1) python networkScan.py ip1
  2) python networkScan.py ip1,ip2,ip3,ip4,ip5,...,ipN
  3) python networkScan.py <rango_ips>
  4) python networkScan.py -i <fichero_hosts>
 
 *Ejemplo de <rango_ips>:*  192.1.130.1-129






