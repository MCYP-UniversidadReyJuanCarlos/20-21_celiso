#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
#Nombre: Celia Lijo Soria
import os, sys, json
from optparse import OptionParser
import xml.etree.ElementTree as ET
import datetime
from webbrowser import open_new_tab
import warnings

warnings.filterwarnings("ignore")

critical_style = "critical_vulnerability"
high_style = "high_vulnerability"
medium_style = "medium_vulnerability"
low_style = "low_vulnerability"
info_style = "info_vulnerability"

class ListDirectories:
    def __init__(self, method, HTTPResponse, content_lenght, dir, redir):
        self.method = method
        self.HTTPResponse = HTTPResponse
        self.content_lenght = content_lenght
        self.dir = dir
        self.redir = redir

class Directories:
    def __init__(self, port, list_directories):
        self.port = port
        self.list_directories = list_directories

class Ports:
    def __init__(self, protocol, port, service, product, version, state):
        self.protocol = protocol
        self.port = port
        self.service = service
        self.product = product
        self.version = version
        self.state = state

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
    def __init__(self, ip, vulnerabilidades, data_ports, directories):
        self.ip = ip
        self.vulnerabilidades = vulnerabilidades
        self.data_ports = data_ports
        self.directories = directories


def envuelveDatosEnHTML(ipList, modo_agresivo, list_http):

    ahora = datetime.datetime.today().strftime("%Y%m%d-%H%M%S")

    print("\nGenerating HTML report...")

    nombreArchivo = "Vulnerability_Assesment_Report_" + ahora + "_1.html"
    f = open(nombreArchivo,'w')

    data_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="./Herramientas/HTML/salesforce-lightning-design-system.min.css">
    <title>Report</title>
    <style>
        .slds-theme_warning {
            color: white !important;
        }

        .slds-theme_warning, .slds-theme--warning{
        background-color:#fe9339;
        color:#080707;
        }
        .slds-theme_warning a, .slds-theme--warning a{
        color:#080707;
        text-decoration:underline;
        }
        .slds-theme_warning a:link, .slds-theme_warning a:visited, .slds-theme--warning a:link, .slds-theme--warning a:visited{
        color:#080707;
        }
        .slds-theme_warning a:hover, .slds-theme_warning a:focus, .slds-theme--warning a:hover, .slds-theme--warning a:focus{
        text-decoration:none;
        }
        .slds-theme_warning a:focus, .slds-theme--warning a:focus{
        -webkit-box-shadow:0 0 3px #514f4d;
                box-shadow:0 0 3px #514f4d;
        border:1px solid #514f4d;
        }
        .slds-theme_warning a:active, .slds-theme--warning a:active{
        color:#514f4d;
        }
        .slds-theme_warning a[disabled], .slds-theme--warning a[disabled]{
        color:#514f4d;
        }
        .slds-theme_warning button, .slds-theme--warning button{
        color:#514f4d;
        text-decoration:underline;
        }
        .slds-theme_warning button:hover, .slds-theme--warning button:hover{
        color:#706e6b;
        }
        .slds-theme_warning button:focus, .slds-theme--warning button:focus{
        color:#514f4d;
        -webkit-box-shadow:0 0 3px #514f4d;
                box-shadow:0 0 3px #514f4d;
        border:1px solid #514f4d;
        }
        .slds-theme_warning button:active, .slds-theme--warning button:active{
        color:#706e6b;
        }
        .slds-theme_warning .slds-icon,
        .slds-theme_warning .slds-button__icon, .slds-theme--warning .slds-icon,
        .slds-theme--warning .slds-button__icon{
        fill:#514f4d;
        }
        
        .slds-theme_error, .slds-theme--error{
        color:white;
        background-color:#ea001e;
        }

        .slds-theme_success, .slds-theme--success{
        color:white;
        background-color:#2e844a;
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
</head>"""

    data_html = data_html + """<body>
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
        data_html = data_html + """<li class="slds-wrap slds-m-horizontal_xx-large"><a href="#ip-"""+ str(j) + """">VULNERABILITIES ASSESMENT OF """ + ip.ip + "</a></li></br>"
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
            <h3  class="slds-text-heading_small"><b>VULNERABILITIES ASSESMENT OF """ + ip.ip + """</b></h3>
            <div class="slds-m-horizontal_xx-large">
                <br/></br>
                <ul class="slds-text-heading_small"><li>Vulnerabilities summary:</li></ul>
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
                <ul class="slds-text-heading_small"><li>Equipment visibility:</li></ul>
                <br/></br>
                <table class="slds-table slds-table_cell-buffer slds-no-row-hover slds-table_bordered slds-table_col-bordered" aria-label="Example table of Opportunities with vertical borders"> 
                    <thead>
                        <tr class="slds-line-height_reset">
                            <th class="" scope="col">
                                <div class="slds-truncate" title="IP">IP</div>
                            </th>
                            <th class="" scope="col">
                                <div class="slds-truncate" title="Protocol">Protocol</div>
                            </th>
                            <th class="" scope="col">
                                <div class="slds-truncate" title="Port1">Port</div>
                            </th>
                            <th class="" scope="col">
                                <div class="slds-truncate" title="Service">Service</div>
                            </th>
                            <th class="" scope="col">
                                <div class="slds-truncate" title="Product">Product</div>
                            </th>
                            <th class="" scope="col">
                                <div class="slds-truncate" title="Version">Version</div>
                            </th>
                            <th class="" scope="col">
                                <div class="slds-truncate" title="State">State</th></div>
                            </th>
                    </tr>
                    </thead>
                    <tbody>"""
        
        for port in ip.data_ports:
            data_html = data_html + """<tr class="slds-hint-parent">
                            <td data-label="IP">
                                <div class="slds-truncate">""" + ip.ip + """</div>
                            </td>
                            <td data-label="Port">
                                <div class="slds-truncate">""" + port.protocol + """</div>
                            </td>
                            <td data-label="Port">
                                <div class="slds-truncate">""" + port.port + """</div>
                            </td>
                            <td data-label="Service">
                                <div class="slds-truncate">""" + port.service + """</div>
                            </td>
                            <td data-label="Product">
                                <div class="slds-truncate">""" + port.product + """</div>
                            </td>
                            <td data-label="Version">
                                <div class="slds-truncate">""" + port.version +  """</div>
                            </td>
                            <td data-label="State">
                                <div class="slds-truncate">""" + port.state + """</div>
                            </td>
                        </tr>"""

        data_html = data_html + """</tbody>
                </table>
            </div>

            <div class="slds-m-horizontal_xx-large">
                <br/></br>
                <ul class="slds-text-heading_small"><li>List of vulnerabilities:</li></ul>
                <br/></br>
                <table class="slds-table slds-table_cell-buffer slds-no-row-hover slds-table_bordered slds-table_col-bordered" aria-label="Example table of Opportunities with vertical borders"> 
                    <thead>
                        <tr class="slds-line-height_reset">
                            <th class="slds-col slds-size_1-of-6">
                                <div class="slds-truncate" title="Severity">Severity</div>
                            </th>
                            <th class="slds-col slds-size_1-of-6">
                                <div class="slds-truncate" title="Port">Port</div>
                            </th>
                            <th class="slds-col slds-size_1-of-6">
                                <div class="slds-truncate" title="CVE">CVE</div>
                            </th>
                            <th class="slds-col slds-size_1-of-6">
                                <div class="slds-truncate" title="CWE">CWE</div>
                            </th>
                            <th class="slds-col slds-size_1-of-6">
                                <div class="slds-truncate" title="Title">Title</div>
                            </th>
                            <th class="slds-col slds-size_1-of-6">
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
                            <td data-label="Severity" scope="row">
                                <div class="slds-truncate">
                                    <div class="slds-text-align_center slds-box slds-box_xx-small slds-size_1-of-1 """ + style + '">' + vuln.severidad + """</div>
                                </div>
                            </td>
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
            </div>"""

        existe = False

        for h in list_http:
            lh = h.split(":")
            if ip.ip == lh[0]:
                existe = True
                break

        if modo_agresivo and existe:
            data_html = data_html + """<div class="slds-m-horizontal_xx-large">
                    <br/></br>
                    <ul class="slds-text-heading_small"><li> Directory listing :</li></u>"""

            for dir in ip.directories:
                data_html = data_html + """<br/></br>
                    <ol><li class="slds-m-horizontal_xx-large" type="disc">Port """ + dir.port + """:</li></ol>
                    <br/></br>
                    <table class="slds-table slds-table_cell-buffer slds-no-row-hover slds-table_bordered slds-table_col-bordered" aria-label="Example table of Opportunities with vertical borders"> 
                        <thead>
                            <tr class="slds-line-height_reset">
                                <th class="" scope="col">
                                    <div class="slds-truncate" title="Method">Method</div>
                                </th>
                                <th class="" scope="col">
                                    <div class="slds-truncate" title="HTTPResponse">HTTP Response</div>
                                </th>
                                <th class="" scope="col">
                                    <div class="slds-truncate" title="Content-Lenght">Content-lenght</div>
                                </th>
                                <th class="" scope="col">
                                    <div class="slds-truncate" title="Directory">Directory</div>
                                </th>
                                <th class="" scope="col">
                                    <div class="slds-truncate" title="Redirection">Redirection</div>
                                </th>
                        </tr>
                        </thead>
                        <tbody>"""
                for d in dir.list_directories:
                    data_html = data_html + """<tr class="slds-hint-parent">
                                <td data-label="Method">
                                    <div class="slds-truncate">""" + d.method + """</div>
                                </td>
                                <td data-label="HTTPResponse">
                                    <div class="slds-truncate">""" + str(d.HTTPResponse) + """</div>
                                </td>
                                <td data-label="Content-Lenght">
                                    <div class="slds-truncate">""" + d.content_lenght + """</div>
                                </td>
                                <td data-label="Directory">
                                    <div class="slds-truncate">""" + d.dir + """</div>
                                </td>
                                <td data-label="Redirection">
                                    <div class="slds-truncate">""" + d.redir + """</div>
                                </td>
                            </tr>"""
                data_html = data_html + """</tbody>
                    </table>"""

        data_html = data_html + """</div>
        <hr size="2px" color="grey" />
    </div>
</body>
</html>"""

    f.write(data_html)
    f.close()

    print("\nHTML successfully generated!!")

    return nombreArchivo

def main():
    print("\nGenerating HTML report...")
    print("\nHTML successfully generated!!")

if __name__ == "__main__":
    main()
