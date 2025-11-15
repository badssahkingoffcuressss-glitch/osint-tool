#!/usr/bin/env python3
# All-in-One OSINT CLI Tool (Safe & Legal)
# Version: 1.0.1

import os
import sys
import requests
import socket
import whois
import json

# ========= COLORS =========
R = "\033[31m"
G = "\033[32m"
Y = "\033[33m"
C = "\033[36m"
W = "\033[0m"

# ========= BANNER =========
BANNER = f"""
{C}==========================================================
           A L L - I N - O N E   O S I N T
=========================================================={W}

{Y}[01]{W} Website Information
{Y}[02]{W} Phone Number Information
{Y}[03]{W} Find IP Address + Email Server
{Y}[04]{W} Domain Whois Lookup
{Y}[05]{W} Website/IP Location
{Y}[06]{W} Cloud Info Checker
{Y}[07]{W} Domain Age Checker
{Y}[08]{W} User Agent Info
{Y}[09]{W} Active Ports Scan
{Y}[10]{W} BIN Checker
{Y}[11]{W} Subdomain Scanner
{Y}[12]{W} Email Validation
{Y}[13]{W} CMS Detector
{Y}[14]{W} Update Tool

==========================================================
"""

# ============ SAFE GET ============
def safe_get(url):
    try:
        return requests.get(url, timeout=10)
    except:
        return None


# ============ FEATURES ============

def website_info(site):
    if not site.startswith("http"):
        site = "https://" + site
    r = safe_get(site)
    if r:
        print("Status:", r.status_code)
        print("Server:", r.headers.get("Server"))
        print("Content-Type:", r.headers.get("Content-Type"))
    else:
        print("Error loading website")


def phone_info(num):
    print(f"{Y}⚠ Limited offline mode (full requires API){W}")
    print("Length:", len(num))
    if num.startswith("+"):
        print("International format detected")


def find_ip_and_email(site):
    try:
        print("IP:", socket.gethostbyname(site))
    except:
        print("Domain unreachable")


def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        print(w)
    except:
        print("Whois error")


def ip_location(ip):
    r = safe_get(f"http://ip-api.com/json/{ip}")
    if r:
        print(r.json())


def cloud_checker(domain):
    try:
        ip = socket.gethostbyname(domain)
        print("Resolved IP:", ip)
    except:
        print("Invalid domain")


def domain_age(domain):
    try:
        w = whois.whois(domain)
        print("Creation Date:", w.creation_date)
    except:
        print("Error fetching age")


def ua_info(ua):
    print("User-Agent Received:", ua)


def port_scan(host):
    ports = [21, 22, 23, 53, 80, 443, 8080]
    print(f"Scanning {host} ...")
    for p in ports:
        s = socket.socket()
        s.settimeout(1)
        try:
            s.connect((host, p))
            print(f"Port {p} OPEN")
        except:
            pass


def bin_checker(bin_num):
    r = safe_get(f"https://lookup.binlist.net/{bin_num}")
    if r:
        print(r.json())
    else:
        print("BIN lookup failed")


def sub_scan(domain):
    subs = ["www", "mail", "ftp", "cpanel", "webmail", "ns1", "ns2"]
    for s in subs:
        sub = f"{s}.{domain}"
        try:
            ip = socket.gethostbyname(sub)
            print(sub, "->", ip)
        except:
            pass


def email_check(mail):
    if "@" in mail and "." in mail:
        print("Valid Email Format")
    else:
        print("Invalid Email")


def cms_detect(site):
    if not site.startswith("http"):
        site = "http://" + site
    r = safe_get(site)
    if not r:
        print("Site unreachable")
        return

    html = r.text.lower()
    if "wp-content" in html:
        print("CMS: WordPress")
    elif "drupal" in html:
        print("CMS: Drupal")
    elif "joomla" in html:
        print("CMS: Joomla")
    else:
        print("CMS: Unknown")


# ============ UPDATE TOOL ============
def update_tool():
    print(f"{C}Checking for updates...{W}")
    os.system("git pull")


# ============ MENU LOOP ============
def main():
    while True:
        os.system("clear")
        print(BANNER)
        choice = input(f"{G}Select Option → {W}")

        if choice == "1":
            website_info(input("Enter domain: "))
        elif choice == "2":
            phone_info(input("Enter phone: "))
        elif choice == "3":
            find_ip_and_email(input("Domain: "))
        elif choice == "4":
            whois_lookup(input("Domain: "))
        elif choice == "5":
            ip_location(input("IP: "))
        elif choice == "6":
            cloud_checker(input("Domain: "))
        elif choice == "7":
            domain_age(input("Domain: "))
        elif choice == "8":
            ua_info(input("User-Agent: "))
        elif choice == "9":
            port_scan(input("Host: "))
        elif choice == "10":
            bin_checker(input("BIN: "))
        elif choice == "11":
            sub_scan(input("Domain: "))
        elif choice == "12":
            email_check(input("Email: "))
        elif choice == "13":
            cms_detect(input("Website: "))
        elif choice == "14":
            update_tool()
        else:
            print("Invalid Option")

        input(f"\n{C}Press Enter to continue...{W}")


if __name__ == "__main__":
    main()
