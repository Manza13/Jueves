#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#
#   CHARLA BITUP --> DETECCION DE INTRUSOS MEDIANTE PATRONES CON SNORT
#   AUTOR: Ismael Manzanera (Manza)
#   VERSION: 1.1
#
#
# // Por ahora solo funcional en Debian/Linux
# // Proximamente funcional en Windows
#

#Modules#

import os, time, subprocess


#DEF#


def detector_EN():
    if informacion == "y" or informacion == "Y":
        os.system("stdbuf -o0 snort -A console --daq dump -q -c /etc/snort/snort.conf -i eth0")
    else:
        a = subprocess.Popen("stdbuf -o0 snort -A console --daq dump -q -c /etc/snort/snort.conf -i eth0".split(), stdout=subprocess.PIPE, bufsize=1)
        for output in a.stdout:
            #print(str(output))
            if 'NMAP' in output.decode("utf-8"):
                print("(%s) NMAP attack detected" % date)
                os.system('notify-send "Jueves" "NMAP attack detected"')
            if 'SNMP' in output.decode("utf-8"):
                print("(%s) Attack via SNMP - Possible port scanning" % date)
                os.system('notify-send "Jueves" "Possible port scanning"')
            if 'ICMP PING' in output.decode("utf-8"):
                print("(%s) ICMP requests" % date)
                os.system('notify-send "Jueves" "ICMP requests"')
            if 'ICMP Echo Reply' in output.decode("utf-8"):
                print("(%s) ICMP response" % date)
                os.system('notify-send "Jueves" "ICMP response"')
            if 'DDOS mstream client to handler' in output.decode("utf-8"):
                print("(%s) DOS attack mstream client to listen - (You are receiving many packages)" % date)
                os.system('notify-send "Jueves" "DOS attack mstream client to listen"')
            if 'BAD-TRAFFIC' in output.decode("utf-8"):
                print("[!] Searching packages")
            if 'ARP' in output.decode("utf-8"):
                print("[!] Possible ARP attack detected")
                os.system('notify-send "Jueves" "Possible ARP attack detected"')
    print("[*] ERROR [*]")


#
#   Separacion del idioma
#



def detector_ES():
	if informacion == "s" or informacion == "S":
		os.system("stdbuf -o0 snort -A console --daq dump -q -c /etc/snort/snort.conf -i eth0")
	else:
		a = subprocess.Popen("stdbuf -o0 snort -A console --daq dump -q -c /etc/snort/snort.conf -i eth0".split(), stdout=subprocess.PIPE, bufsize=1)
		for output in a.stdout:
			#print(str(output))
			if 'NMAP' in output.decode("utf-8"):
				print("(%s) Ataque de NMAP detectado" % date)
				os.system('notify-send "Jueves" "Ataque de NMAP detectado"')
			if 'SNMP' in output.decode("utf-8"):
				print("(%s) Ataque via SNMP - Posible escaneo de puertos" % date)
				os.system('notify-send "Jueves" "Posible escaneo de puertos"')
			if 'ICMP PING' in output.decode("utf-8"):
				print("(%s) Peticiones de ICMP" % date)
				os.system('notify-send "Jueves" "Peticiones de ICMP"')
			if 'ICMP Echo Reply' in output.decode("utf-8"):
				print("(%s) Respuesta ICMP" % date)
				os.system('notify-send "Jueves" "Respuesta ICMP"')
			if 'DDOS mstream client to handler' in output.decode("utf-8"):
				print("(%s) Ataque DOS mstream cliente a escucha - (Se esta recibiendo muchos paquetes)" % date)
				os.system('notify-send "Jueves" "Ataque DOS mstream cliente a escucha"')
			if 'BAD-TRAFFIC' in output.decode("utf-8"):
				print("[!] Buscando paquetes")
			if 'ARP' in output.decode("utf-8"):
				print("[!] Posible ataque ARP detectado")
				os.system('notify-send "Jueves" "Posible ataque ARP detectado"')
			if 'meterpreter' in output.decode("utf-8"):
				print("[!] Conexion meterpreter detectada via UDP.")
				os.system('notify-send "Jueves" "Conexion meterpreter detectada"')
	print("[*] ERROR [*]")



#Program#
date = time.strftime("%c")

print(""" 
      ██╗██╗   ██╗███████╗██╗   ██╗███████╗███████╗
      ██║██║   ██║██╔════╝██║   ██║██╔════╝██╔════╝
      ██║██║   ██║█████╗  ██║   ██║█████╗  ███████╗
 ██   ██║██║   ██║██╔══╝  ╚██╗ ██╔╝██╔══╝  ╚════██║
 ╚█████╔╝╚██████╔╝███████╗ ╚████╔╝ ███████╗███████║
  ╚════╝  ╚═════╝ ╚══════╝  ╚═══╝  ╚══════╝╚══════╝    
Version: 1.1   Autor: Ismael Manzanera   OS: Linux/Debian
""")
print("\n1.- English [Default]")
print("2.- Español\n")
idioma = str(input("Select your lenguaje / Selecciona tu idioma: "))

if idioma == "2":
	print("\n[!] Bienvenido a Jueves.")
	print("[!] Este programa esta creando un pcap en la misma ruta que Jueves, [LOG]")
	print("[!] Estamos analizando los paquetes por posibles ataques\n")
	informacion = str(input("\n[+] Desea ver informacion mas completa (snort) [s/n]: "))
	detector_ES()
else:
	print("[!] Welcome to Jueves")
	print("[!] This program is creating a pcap on the same route as Jueves, [LOG]")
	print("[!] We are analyzing the packages for possible attacks\n")
	informacion = str(input("\n[+] You want to see more complete information (snort) [y/n]: "))
	detector_EN()
