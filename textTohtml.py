#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
#Nombre: Celia Lijo Soria
import os, sys, json
from optparse import OptionParser
import xml.etree.ElementTree as ET
import warnings

warnings.filterwarnings("ignore")


critical_style = "critical_vulnerability"
high_style = "high_vulnerability"
medium_style = "medium_vulnerability"
low_style = "low_vulnerability"
info_style = "info_vulnerability"

class Vulnerabilidad:

    def __init__(self, cvss, severidad, puerto, cve, cwe, titulo, descripcion):
        self.cvss = cvss
        self.severidad = severidad
        self.puerto = puerto
        self.cve = cve
        self.cwe = cwe
        self.titulo = titulo
        self.descripcion = descripcion

class Ip:

    def __init__(self, ip, vulnerabilidades):
        self.ip = ip
        self.vulnerabilidades = vulnerabilidades


def envuelveDatosEnHTML(ipList):
    import datetime
    from webbrowser import open_new_tab

    print("Generando informe ...")

    ahora = datetime.datetime.today().strftime("%Y%m%d-%H%M%S")


    nombreArchivo = "Vulnerability_Assesment_Report_" + ahora + ".html"
    f = open(nombreArchivo,'wb')

    data_html="""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="./Herramientas/HTML/salesforce-lightning-design-system.css">
    <title>Report</title>
    <style>
        .slds-theme_warning {
            color: white !important;
        }
        
        ul > li {
            list-style-type: circle;
        }
        
        .critical_vulnerability {
            background-color: #5a1ba9;
            color: white;
        }
        
        .high_vulnerability {
            background-color: red;
            color: white;
        }
        
        .medium_vulnerability {
            background-color: orange;
            color: white;
        }
        
        .low_vulnerability {
            background-color: green;
            color: white;
        }
        
        .info_vulnerability {
            background-color: #0176d3;
            color: white;
        }
    </style>
</head>
<body>
    <div class="slds-m-horizontal_xx-large">
        <div class="slds-text-heading_large">
            </br>
            <hr size="2px" color="grey" />
            <h1><b>REPORT OF VULNERABILITIES ASSESMENTS</b></h1>
        </div>
        <hr size="2px" color="grey" />         
        <div class="slds-text-heading_small">
            <h3><b>TABLE OF CONTENTS</b></h3>
            </br>
            <ul>"""
    j=1
    for ip in ipList:
        data_html = data_html + """<li class="slds-wrap slds-m-horizontal_xx-large"><a href="#ip-"""+ str(j) + """">VULNERABILITY ASSESMENT OF """ + ip.ip + "</a></li></br>"
        j = j + 1

    data_html = data_html + """</ul>
        </div>
        <hr size="2px" color="grey" />"""
    
    j=1
    for ip in ipList:

        num_criticas = 0
        num_altas = 0
        num_medias = 0
        num_bajas = 0
        num_info = 0

        for vul in ip.vulnerabilidades:
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

        data_html = data_html + """<div id="ip-""" + str(j) + """">
            <h3  class="slds-text-heading_small"><b>VULNERABILITY ASSESMENT OF """ + ip.ip + """</b></h3>
            <div class="slds-m-horizontal_xx-large">
                <br/></br>
                <ul class="slds-text-heading_small"><li>Vulnerability summary:</li></ul>
                <br/></br>
                <div class="slds-grid slds-wrap slds-m-horizontal_xx-large">
                    <div class="slds-col slds-size_1-of-5">
                        <article class="slds-card critical_vulnerability">
                            <div class="slds-card__body slds-card__body_inner slds-m-around_x-large slds-text-heading_large slds-align_absolute-center">""" + str(num_criticas) + """</div>
                            <footer class="slds-card__footer">
                                <div class="slds-text-heading_small slds-align_absolute-center">Critical</div>
                            </footer>
                        </article>
                    </div>
                    <div class="slds-col slds-size_1-of-5">
                        <article class="slds-card slds-theme_error">
                            <div class="slds-card__body slds-card__body_inner slds-m-around_x-large slds-text-heading_large slds-align_absolute-center">""" + str(num_altas) + """</div>
                            <footer class="slds-card__footer">
                                <div class="slds-text-heading_small slds-align_absolute-center">High</div>
                            </footer>
                        </article>
                    </div>
                    <div class="slds-col slds-size_1-of-5">
                        <article class="slds-card slds-theme_warning">
                            <div class="slds-card__body slds-card__body_inner slds-m-around_x-large slds-text-heading_large slds-align_absolute-center">""" + str(num_medias) + """</div>
                            <footer class="slds-card__footer">
                                <div class="slds-text-heading_small slds-align_absolute-center">Medium</div>
                            </footer>
                        </article>
                    </div>
                    <div class="slds-col slds-size_1-of-5">
                        <article class="slds-card slds-theme_success">
                            <div class="slds-card__body slds-card__body_inner slds-m-around_x-large slds-text-heading_large slds-align_absolute-center">""" + str(num_bajas) + """</div>
                            <footer class="slds-card__footer">
                                <div class="slds-text-heading_small slds-align_absolute-center">Low</div>
                            </footer>
                        </article>
                    </div>
                    <div class="slds-col slds-size_1-of-5">
                        <article class="slds-card info_vulnerability">
                            <div class="slds-card__body slds-card__body_inner slds-m-around_x-large slds-text-heading_large slds-align_absolute-center">""" + str(num_info) + """</div>
                            <footer class="slds-card__footer">
                                <div class="slds-text-heading_small slds-align_absolute-center">Info</div>
                            </footer>
                        </article>
                    </div>
                </div>
            </div>
            <div class="slds-m-horizontal_xx-large">
                <br/></br>
                <ul class="slds-text-heading_small"><li>Vulnerability table:</li></ul>
                <br/></br>
                <table class="slds-table slds-table_cell-buffer slds-no-row-hover slds-table_bordered slds-table_col-bordered" aria-label="Example table of Opportunities with vertical borders"> 
                    <thead>
                        <tr class="slds-line-height_reset">
                            <th class="" scope="col">
                                <div class="slds-truncate" title="Severity">Severity</div>
                            </th>
                            <th class="" scope="col">
                                <div class="slds-truncate" title="Port">Port</div>
                            </th>
                            <th class="" scope="col">
                                <div class="slds-truncate" title="CVE">CVE</div>
                            </th>
                            <th class="" scope="col">
                                <div class="slds-truncate" title="CWE">CWE</div>
                            </th>
                            <th class="" scope="col">
                                <div class="slds-truncate" title="Title">Title</div>
                            </th>
                            <th class="" scope="col">
                                <div class="slds-truncate" title="Description">Description</div>
                            </th>
                        </tr>
                    </thead>
                    <tbody>"""
        j=j+1
        for vuln in ip.vulnerabilidades:
            
            if vuln.severidad.upper() == "CRITICAL":
                style = critical_style
            elif vuln.severidad.upper() == "HIGH":
                style = high_style
            elif vuln.severidad.upper() == "MEDIUM":
                style = medium_style
            elif vuln.severidad.upper() == "LOW":
                style = low_style
            else:
                style = info_style

            data_html = data_html + """<tr class="slds-hint-parent">
                            <th data-label="Severity" scope="row">
                                <div class="slds-truncate">
                                    <div class="slds-text-align_center slds-box slds-box_xx-small slds-size_1-of-2 """ + style + '">' + vuln.severidad + """</div>
                                </div>
                            </th>
                            <td data-label="Port">
                                <div class="slds-truncate">""" + vuln.puerto + """</div>
                            </td>
                            <td data-label="CVE" class="slds-cell-wrap">
                                <div class="slds-truncate slds-line-clamp">""" + vuln.cve + """</div>
                            </td>
                            <td data-label="Prospecting">
                                <div class="slds-truncate">""" + vuln.cwe + """</div>
                            </td>
                            <td data-label="Title">
                                <div class="slds-truncate">""" + vuln.titulo + """</div>
                            </td>
                            <td data-label="Description" class="slds-cell-wrap">
                                <div class="slds-truncate slds-line-clamp">""" + vuln.descripcion + """</div>
                            </td>
                        </tr>"""

        data_html = data_html + """</tbody>
                </table>
            </div>
            <hr size="2px" color="grey" />
        </div>"""
    
    data_html = data_html + """    </div>
</body>
</html>"""

    f.write(data_html)
    f.close()
    print("\nInforme generado con exito!!")


def main():
    print("Generando informe ...")
    #envuelveDatosEnHTML()
    print("\nInforme generado con exito!!")

if __name__ == "__main__":
    main()
