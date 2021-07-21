#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
#Nombre: Celia Lijo Soria
import os, sys, json
from optparse import OptionParser
from typing import Protocol
import xml.etree.ElementTree as ET
import warnings
import pdfkit

warnings.filterwarnings("ignore")

critical_style = "critical_vulnerability"
high_style = "high_vulnerability"
medium_style = "medium_vulnerability"
low_style = "low_vulnerability"
info_style = "info_vulnerability"

SSHlist = []
TLSlist = []
SMBlist = []
PortsList = []

def envuelveDatosEnHTML(ipList):
    import datetime
    from webbrowser import open_new_tab

    ahora = datetime.datetime.today().strftime("%Y%m%d-%H%M%S")

    print("Generando informe ...")

    nombreArchivo = "Vulnerability_Assesment_Report_" + ahora + ".html"
    f = open(nombreArchivo,'w')

    header_html="""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0"> 
    <title>Report</title>
    <style>
        .slds-m-horizontal_xx-large{
            margin-left:1em;
            margin-right:1rem;
        }

        .slds-text-heading_large,
        .slds-text-heading--large{
            font-size:1.75rem;
            line-height:1.25;
        }

        .slds-text-heading_small,
        .slds-text-heading--small{
            font-size:1rem;
            line-height:1.25;
        }

        .slds-popover_walkthrough-alt .slds-text-heading_small,
        .slds-popover_feature .slds-text-heading_small{
            margin-bottom:0.5rem;
        }

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

        .slds-text-heading_large {
            font-size:1.3rem;
            line-height:1.25;
        }

        .slds-text-heading_small {
            font-size:1.2rem;
            line-height:1.5;
        }

        .slds-size_1-of-5 {
            width:20%;
        }

        .slds-box {
            text-align:center;
            padding:0.15rem;
            border-radius:0.25rem;
            border:1px solid #dddbda;
            <!---width:50%;--->
        }

        .slds-line-height_reset{
            line-height:1;
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

        body {
            background: #fafafa 
            color: #444;
            font: 100%/30px 'Helvetica Neue', helvetica, arial, sans-serif;
            text-shadow: 0 1px 0 #fff;
        }
        
        strong {
            font-weight: bold; 
        }
        
        em {
            font-style: italic; 
        }
        
        table {
            background: #f5f5f5;
            border-collapse: separate;
            border: 1px solid black;
            box-shadow: inset 0 1px 0 #fff;
            font-size: 12px;
            line-height: 24px;
            margin: 30px auto;
            text-align: center;
            width: 1000px;
        }	

        #table_vulns {
            width: 1400px;
        }

        #table_title {
            background: #b1aeae;
        }

        th, td {
            text-align: center;
            border: 1px solid black;
        }
    </style>
</head>"""

    data_html="""<body>
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
    
    for ip in ipList:
        data_html = data_html + """<li class="slds-m-horizontal_xx-large">VULNERABILITIES ASSESMENT OF """ + ip.ip + "</a></li></br>"

    data_html = data_html + """</ul>
            </br>
        </div>
        <hr size="2px" color="grey" />"""
    
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

        data_html = data_html + """<div>
            <h3  class="slds-text-heading_small"><b>VULNERABILITIES ASSESMENT OF """ + ip.ip + """</b></h3>
            <div class="slds-m-horizontal_xx-large">
                <br/>
                <ul class="slds-text-heading_small"><li>Vulnerabilities summary:</li></ul>
                <div class="slds-m-horizontal_xx-large slds-text-heading_large" align="center" style="width:auto">
                    <table>
                        <thead>
                          <tr>
                            <th class="critical_vulnerability slds-text-heading_large slds-size_1-of-5">""" + str(num_criticas) + """</th>
                            <th class="high_vulnerability slds-text-heading_large slds-size_1-of-5">""" + str(num_altas) + """</th>
                            <th class="medium_vulnerability slds-text-heading_large slds-size_1-of-5">""" + str(num_medias) + """</th>
                            <th class="low_vulnerability slds-text-heading_large slds-size_1-of-5">""" + str(num_bajas) + """</th>
                            <th class="info_vulnerability slds-text-heading_large slds-size_1-of-5">""" + str(num_info) + """</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr>
                            <td class="critical_vulnerability slds-text-heading_large slds-size_1-of-5">CRITICAL</td>
                            <td class="high_vulnerability slds-text-heading_large slds-size_1-of-5">HIGH</td>
                            <td class="medium_vulnerability slds-text-heading_large slds-size_1-of-5">MEDIUM</td>
                            <td class="low_vulnerability slds-text-heading_large slds-size_1-of-5">LOW</td>
                            <td class="info_vulnerability slds-text-heading_large slds-size_1-of-5">INFO</td>
                          </tr>
                        </tbody>
                      </table>
                </div>
            </div>
                
            <div class="slds-m-horizontal_xx-large">
                <ul class="slds-text-heading_small"><li>Equipment visibility:</li></ul>
                <div class="slds-m-horizontal_xx-large slds-text-heading_large" align="center" style="width:auto">
                    <table id="table_ports">
                        <thead>
                        <tr id="table_title">
                            <th class="slds-text-heading_small slds-size_1-of-6">IP</th>
                            <th class="slds-text-heading_small slds-size_1-of-6">Protocol</th>
                            <th class="slds-text-heading_small slds-size_1-of-6">Port</th>
                            <th class="slds-text-heading_small slds-size_1-of-6">Service</th>
                            <th class="slds-text-heading_small slds-size_1-of-6">Product</th>
                            <th class="slds-text-heading_small slds-size_1-of-6">Version</th>
                            <th class="slds-text-heading_small slds-size_1-of-6">State</th>
                        </tr>
                        </thead>
                        <tbody>"""
        for port in ip.data_ports:
            data_html = data_html + '<tr><td>' + ip.ip + '</td><td>' + port.protocol + '</td><td>' + port.port + '</td><td>' + port.service + '</td><td>' + port.product + '</td><td>' + port.version +  '</td><td>' + port.state + '</td></tr>'

        data_html = data_html +"""</tbody>
                    </table>
                </div>
            </div>

            <div class="slds-m-horizontal_xx-large">
                <ul class="slds-text-heading_small"><li>List of vulnerabilities:</li></ul>
                <div class="slds-m-horizontal_xx-large slds-text-heading_large" align="center" style="width:auto">
                    <table id="table_vulns">
                        <thead>
                        <tr id="table_title" class="slds-line-height_reset">
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
                        <tbody id="flotante">"""
        
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
                                        <div class="slds-box """ + style + '">' + vuln.severidad + """</div>
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
                </div>
            </div>
            <hr size="2px" color="grey" />"""
    
    data_html = data_html + """
        </div>
</body>
</html>"""

    f.write(header_html+data_html)
    f.close()

    return nombreArchivo

def ToPdf (nombreArchivo):
    print("Generando informe en pdf...")
    nombre = nombreArchivo.split(".")
    options = {'quiet': ''}
    pdfkit.from_file(nombreArchivo, nombre[0] + ".pdf", options=options)
    print("\nPDF generado con exito!!")

def main():
    print("Generando informe en pdf...")
    #ToPdf("html_prueba.html")
    print("\nPDF generado con exito!!")

if __name__ == "__main__":
    main()
