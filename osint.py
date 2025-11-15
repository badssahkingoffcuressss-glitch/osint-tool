#!/usr/bin/env python3
# All-in-One OSINT CLI Tool (Safe & Legal)
# Works on Termux / UserLand / Kali (Non-Root)
# Version: 1.0.0

import os
import sys
import requests
import socket
import whois
import json

# ============= COLORS =============
R = "[31m"
G = "[32m"
Y = "[33m"
B = "[34m"
C = "[36m"
W = "[0m"

# ============= BANNER =============
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
{Y}[09]{W} Active Ports Scan (Safe)
{Y}[10]{W} BIN Checker
{Y}[11]{W} Subdomain Scanner
{Y}[12]{W} Email Validation
{Y}[13]{W} CMS Detector
{Y}[14]{W} Update Tool (Auto Update)

==========================================================
"""

# ============= UTILS =============
def safe_get(url):
    try:
        return requests.get(url, timeout=10)
    except:
        return None

# ============= FEATURES =============
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
    print(f"{Y}⚠ Limited offline mode (full requires API key){W}")
    if num.startswith("+"):
        print("Format OK: International")
    print("Possible Country Code:", num[:3])


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
    ip = socket.gethostbyname(domain)
    print("Resolved IP:", ip)


def domain_age(domain):
    try:
        w = whois.whois(domain)
        print("Creation Date:", w.creation_date)
    except:
        print("Error fetching age")


def ua_info(ua):
    print("User-agent received:")

", ua)


def port_scan(host):
    ports = [21, 22, 80, 443, 8080]
    for p in ports:
        s = socket.socket()
        s.settimeout(1)
        try:
            s.connect((host, p))
            print(f"Port {p} open")
        except:
            pass


def bin_checker(bin_num):
    r = safe_get(f"https://lookup.binlist.net/{bin_num}")
    if r:
        print(r.json())


def sub_scan(domain):
    subs = ["www", "mail", "ftp", "cpanel", "webmail"]
    for s in subs:
        sub = f"{s}.{domain}"
        try:
            ip = socket.gethostbyname(sub)
            print(sub, "->", ip)
        except:
            pass


def email_check(mail):
    if "@" in mail:
        print("Format OK")
    else:
        print("Invalid format")


def cms_detect(site):
    if not site.startswith("http"):
        site = "http://" + site
    r = safe_get(site)
    if not r:
        print("Site unreachable")
        return
    html = r.text.lower()
    if "wp-content" in html:
        print("WordPress detected")
    elif "drupal" in html:
        print("Drupal detected")
    elif "joomla" in html:
        print("Joomla detected")
    else:
        print("Unknown CMS")

# ============= 14. UPDATE TOOL =============

def update_tool():
    print(f"{C}Checking for updates...{W}")
    repo_url = "https://raw.githubusercontent.com/badssahkingoffcuressss-glitch/osint-tool/main/osint.py"

