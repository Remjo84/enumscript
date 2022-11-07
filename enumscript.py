#!/usr/bin/env python

#######################################
#    Author: Rémy Cervenka            #
#    Linkedin: /in/rémy-cervenka/     #
#######################################

#import modules
import sys
from time import sleep
import os
import subprocess
import shlex
import shutil
import pyfiglet
import webtech

#global scan_type 
#scan_type = 0
domain_data = ""
ip_data = ""

def print_ascii_art():
    ascii_banner = pyfiglet.figlet_format("Recoil \n Enumeration \nScript")
    print('\33[32m'+ascii_banner+'\33[0m')


def splitter():
    print('\033[91m'+'-'*60+'\033[0m')


def menu():
    print_ascii_art()
    print()



    choice = input("""
                      1: External passive scan
                      2: External active scan
                      3. External active scan for specific domains
                      4. Internal single host scan
                      5: Internal scan
                      6: Update tools
                      7: Install tools
                      8: Exit

                      Please enter your choice: """)

    if choice == "1":
        input_passive_domain()
    elif choice == "2":
        input_active_domain()
    elif choice == "3":
        input_active_domain_specific()
    elif choice=="4":
        input_ip_single()
    elif choice=="5":
        input_ip()
    elif choice=="6":
        update()
    elif choice=="7":
        install()
    elif choice=="8":
        sys.exit
    else:
        print("You must only select either 1, 2, 3, 4, 5, 6 or 7")
        print("Please try again")
        menu()


# CREATE DATA DIRECTORY

def mkdir(path):
    print('\033[91m'+'Sorting directories...'+'\033[0m')
    sleep(1)
    if os.path.exists(path):
        print('Directory already exists'+'\n'+'Using existing directory')
    else:
        print('Creating directory...')
        try:
            os.makedirs(path)
        except OSError:
            print('Creation of the directory failed...')
        else:
            print('Successfully created the directory!')

# INPUT

def input_passive_domain():
    splitter()
    domain = input('\033[91m'+'Enter domain name: '+'\033[0m')
    parent_dir = "external_passive"
    path = os.path.join(parent_dir, domain)
    print(f'Working on gathering info on {domain}')
    external_passive(path,domain)

def input_active_domain():
    splitter()
    domain = input('\033[91m'+'Enter domain name: '+'\033[0m')
    parent_dir = "external_active"
    path = os.path.join(parent_dir, domain)
    print(f'Working on gathering info on {domain}')
    external_active(path,domain)

def input_active_domain_specific():
    splitter()
    print("Press ENTER to use default hosts.txt and ip-hosts.txt list")
    default_domain_input_list = "hosts.txt"
    default_ip_input_list = "ip-hosts.txt"
    file_input_domain = input('\033[91m'+'Enter domain file name: '+'\033[0m') or default_domain_input_list
    file_input_ip = input('\033[91m'+'Enter ip-host file name: '+'\033[0m') or default_ip_input_list
    project = input('\033[91m'+'Enter project name: '+'\033[0m')
    parent_dir = ("external_specific/")
    path = os.path.join(parent_dir, project)

    print(f'Working on gathering domains from {file_input_domain} and {file_input_ip}')

    #calling file combiner
    with open (file_input_domain) as fp:
        domain_data = fp.read()

    with open (file_input_ip) as fp:
        ip_data = fp.read()

    domain_data += "\n"
    domain_data += ip_data

    with open (f'{path}/combined-file.txt', 'w') as fp:
        fp.write(domain_data)

    domain = domain_data
    
    external_specific(domain,path,file_input_domain,file_input_ip)

def input_ip_single():
    splitter()
    ip = input('\033[91m'+'Enter a single IP-address, for example: 192.168.10.70: '+'\033[0m')
    parent_dir = "internal_single"
    path = os.path.join(parent_dir, ip)
    print(f'Working on gathering info on {ip}')

    internal_single(ip,path)

def input_ip():
    splitter()
    ip = input('\033[91m'+'Enter IP subnet, for example: 192.168.10.0: '+'\033[0m')
    subnetmask = input('\033[91m'+'Enter subnet mask, for example: 8, 16 or 24: '+'\033[0m')
    parent_dir = "internal"
    path = os.path.join(parent_dir, ip)
    print(f'Working on gathering info on {ip}/{subnetmask}')

    internal(ip,subnetmask,path)

# TEST TYPE CHOICES

def external_passive(path,domain):
    mkdir(path)
    scan_type = 1
    file_input_domain = ""

    #calling functions (tools)
    wafw00f(domain,path,file_input_domain,scan_type)
    wig(domain,path,file_input_domain,scan_type)
    subdomainizer(domain,path,file_input_domain,scan_type)
    amass(domain,path)
    subfinder(domain)
    #gitdorker()
    shodan_nmap(domain,path)
    testssl(domain,path,file_input_domain,scan_type)
    print('\033[91m'+'Scan is completed'+'\033[0m')

def external_active(path,domain):
    mkdir(path)
    scan_type = 2
    file_input_domain = ""
    file_input_ip = ""
    ip = ""
    subnetmask = ""

    #calling functions (tools)
    amass(domain,path)
    nmap_web(file_input_ip,file_input_domain,ip,subnetmask,path,scan_type)
    yasuo_web(path,scan_type)
    wafw00f(domain,path,file_input_domain,scan_type)
    subdomainizer(domain,path,file_input_domain,scan_type)
    subfinder(domain)
    linkfinder(domain,path,file_input_domain,scan_type)
    testssl_subdomains(path)
    nikto(path,file_input_domain,scan_type)
    whatcms(domain)
    wig(domain,path,file_input_domain,scan_type)
    nmap_full(domain,path,scan_type)
    nmap_subdomains(path)
    print('\033[91m'+'Scan is completed'+'\033[0m')

def external_specific(domain,path,file_input_domain,file_input_ip):
    mkdir(path)
    scan_type = 3
    ip = ""
    subnetmask = ""

    #calling functions (tools)
    nmap_web(file_input_ip,file_input_domain,ip,subnetmask,path,scan_type)
    nmapparser(path)
    wafw00f(domain,path,file_input_domain,scan_type)
    wig(domain,path,file_input_domain,scan_type)
    subdomainizer(domain,path,file_input_domain,scan_type)
    linkfinder(domain,path,file_input_domain,scan_type)
    testssl(domain,path,file_input_domain,scan_type)
    nikto(path,file_input_domain,scan_type)
    yasuo_web(path,scan_type)
    nmap_full(domain,path,scan_type)
    yasuo_all(path,ip,subnetmask,scan_type)
    print('\033[91m'+'Scan is completed'+'\033[0m')

def internal_single(ip,path):
    mkdir(path)
    scan_type = 4
    domain = ip
    nmapautomator_fast = True
    nmapautomator_full = True
    nmapautomator_vuln = True
    nmapautomator_recon = True
    
    #calling functions (tools)
    # NmapAutomator fast port scan
    
    nmapautomator(ip,path,nmapautomator_fast,nmapautomator_full,nmapautomator_vuln,nmapautomator_recon)
    # NmapAutomator full and script port scan
    nmapautomator_fast = False
    nmapautomator(ip,path,nmapautomator_fast,nmapautomator_full,nmapautomator_vuln,nmapautomator_recon)
    # Webtech
    webtech(ip)
    # Whatcms
    whatcms(domain)
    # NmapAutomator vuln scan
    nmapautomator_full = False
    nmapautomator(ip,path,nmapautomator_fast,nmapautomator_full,nmapautomator_vuln,nmapautomator_recon)
    # NmapAutomator recon mode
    nmapautomator_vuln = False
    nmapautomator(ip,path,nmapautomator_fast,nmapautomator_full,nmapautomator_vuln,nmapautomator_recon)

def internal(ip,subnetmask,path):
    mkdir(path)
    scan_type = 5
    file_input_domain = ""
    file_input_ip = ""
    domain = ""

    #calling functions (tools)
    nmap_web(file_input_ip,file_input_domain,ip,subnetmask,path,scan_type)
    yasuo_web(path,scan_type)
    nmapparser(path)
    wig(domain,path,file_input_domain,scan_type)
    nmap_full(domain,path,ip,subnetmask,scan_type)
    yasuo_all(path,ip,subnetmask,scan_type)
    nikto(path,file_input_domain,scan_type)

# TOOLS


def wafw00f(domain,path,file_input_domain,scan_type):
    splitter()
    if scan_type == 3:
        print("\033[91mChecking for WAF on specified hosts\033[0m")
        subprocess.run(shlex.split(f'wafw00f -i {file_input_domain} -o {path}/wafw00f-domain.txt'))
        subprocess.run(shlex.split(f'wafw00f -i {path}/hosts_web_ip.txt -o {path}/wafw00f-ip.txt'))
    else:
        print("\033[91mChecking for WAF\033[0m")
        #path_wafw00f = ("tools/wafw00f/wafw00f/main.py")
        #args = ("-o")
        #output_wafw00f = (f"{path}/wafw00f.txt")
        #subprocess.run([sys.executable, path_wafw00f, domain, args, output_wafw00f])
        subprocess.run(shlex.split(f'wafw00f {domain} -o {path}/wafw00f.txt'))

def wig(domain,path,file_input_domain,scan_type):
    splitter()
    print("\033[91mRunning WebApp Information Gatherer\033[0m")
    if scan_type == 3:
        subprocess.run(shlex.split(f'tools/wig/wig.py -l {file_input_domain} -q --no_cache_load --no_cache_save -w {path}/wig-domain'))
        subprocess.run(shlex.split(f'tools/wig/wig.py -l {path}/hosts_web_ip.txt -q --no_cache_load --no_cache_save -w {path}/wig-domain'))
    if scan_type == 5:
        subprocess.run(shlex.split(f'tools/wig/wig.py -l {path}/hosts_web_ip.txt -q --no_cache_load --no_cache_save -w {path}/wig'))
    else: 
        subprocess.run(shlex.split(f'tools/wig/wig.py {domain} -q --no_cache_load --no_cache_save -w {path}/wig'))

def subdomainizer(domain,path,file_input_domain,scan_type):
    splitter()
    if scan_type == 3:
        print("\033[91mRunning SubDomainizer\033[0m")
        subprocess.run(shlex.split(f'tools/SubDomainizer/SubDomainizer.py -l {file_input_domain} -o {path}/subdomainizer_spec'))
    else:
        print("\033[91mRunning SubDomainizer\033[0m")
        path_subdomainizer = ("tools/SubDomainizer/SubDomainizer.py")
        args = ("-u")
        output = ("-o")
        output_subdomainizer = (f"{path}/subdomainizer")
        subprocess.run([sys.executable, path_subdomainizer, args, domain, output, output_subdomainizer])

def amass(domain,path):
    splitter()
    print("\033[91mRunning Amass to search for subdomains\033[0m")
    subprocess.run(shlex.split(f'tools/amass_linux_amd64/amass enum -d {domain} -oA {path}/amass'))

def subfinder(domain):
    splitter()
    print("\033[91mRunning Subfinder to find http subdomains\033[0m")
    subprocess.run(shlex.split(f'subfinder -d {domain} |httpx - csp-probe -title -status'))

#def gitdorker(domain)
    #splitter()
    #print("\033[91mRunning GitHub enumeration\033[0m")
    #subprocess.run(shlex.split(f'tools/GitDorker/GitDorker.py -tf tools/GitDorker/token -q {domain} -d tools/GitDorker/Dorks/alldorksv3 -o {domain}/gitdorker'))

def shodan_nmap(domain,path):
    splitter()
    print("\033[91mRunning Shodan port check via Nmap\033[0m")
    subprocess.run(shlex.split(f'nmap -sn -Pn -n --script shodan-api --script-args shodan-api.apikey=v4yHwIDvHonnAEf6IsimyDRacbvm4RY5 {domain} -oA {path}/nmap_shodan_passive'))

    splitter()
    print("\033[91mRunning Shodan port check on subdomains via Nmap\033[0m")
    subprocess.run(shlex.split(f'nmap -sn -Pn -n --script shodan-api --script-args shodan-api.apikey=v4yHwIDvHonnAEf6IsimyDRacbvm4RY5 -iL {path}/amass.txt -oA {path}/nmap_shodan_passive_sub'))

def testssl(domain,path,file_input_domain,scan_type):
    splitter()
    if scan_type == 3:
        print("\033[91mRunning SSL and Security Headers check\033[0m")
        subprocess.run(shlex.split(f'tools/testssl.sh/testssl.sh -oA {path}/testssl --append -iL {file_input_domain}'))
    else:
        print("\033[91mRunning SSL and Security Headers check\033[0m")
        subprocess.run(shlex.split(f'tools/testssl.sh/testssl.sh -oA {path}/testssl --append {domain}'))

def testssl_subdomains(path):
    splitter()
    print("\033[91mRunning SSL and Security Headers check on subdomains\033[0m")
    subprocess.run(shlex.split(f'tools/testssl.sh/testssl.sh -oA {path}/testssl_check_all --append -iL {path}/amass.txt'))

def nmap_web(file_input_ip,file_input_domain,ip,subnetmask,path,scan_type):
    splitter()
    if scan_type == 3:
        print("\033[91mSearching for open web ports on IP addresses\033[0m")
        subprocess.run(shlex.split(f'nmap -p 80,8080,8000,8001,8008,443,4443,8443,5000,5001,9443 -sV --open -iL {file_input_ip} -oA {path}/nmap_web_ip'))
        #subprocess.run(shlex.split(f'nmap -p http* --open -sV -iL {file_input_ip} -oA {path}/nmap_web'))
        
        splitter()
        print("\033[91mSearching for open web ports on domain names\033[0m")
        subprocess.run(shlex.split(f'nmap -p 80,8080,8000,8001,8008,443,4443,8443,5000,5001,9443 -sV --open -iL {file_input_domain} -oA {path}/nmap_web_domain'))
        #subprocess.run(shlex.split(f'nmap -p http* --open -sV -iL {file_input_domain} -oA {path}/nmap_web_domain'))
    elif scan_type == 5:
        print("\033[91mRunning port scan on web ports\033[0m")
        subprocess.run(shlex.split(f'nmap -p 80,8080,8000,8001,8008,443,8443,5000,5001 {ip}/{subnetmask} --open -oA {path}/nmap_web_ip'))
    else:
        print("\033[91mRunning port scan on web ports\033[0m")
        subprocess.run(shlex.split(f'nmap -p 80,8080,8000,8001,8008,443,8443,5000,5001 --open -iL {path}/amass.txt -oA {path}/nmap_web'))
        os.system(f'tools/nmap-parse-output/nmap-parse-output {path}/nmap_web.xml hosts > {path}/hosts_web.txt')

def nmap_full(domain,path,ip,subnetmask,scan_type):
    splitter()
    if scan_type == 3:
        print(f"\033[91mRunning port scan on all ports\033[0m")
        subprocess.run(shlex.split(f'nmap -p- --open -vv -iL {path}/combined-file.txt -oA {path}/nmap-full-scan'))
    if scan_type == 5:
        print(f"\033[91mRunning port scan on {ip}/{subnetmask} on all ports\033[0m")
        subprocess.run(shlex.split(f'nmap -p- {ip}/{subnetmask} -vv --open -oA {path}/nmap-full-scan'))
    else:
        print("\033[91mRunning port scan on all ports\033[0m")
        subprocess.run(shlex.split(f'nmap -p- --open -vv {domain} -oA {path}/nmap'))

def yasuo_web(path,scan_type):
    splitter()
    if scan_type == 3:
        print("\033[91mRunning vulnerability scan on webapp ports\033[0m")
        cwd = os.getcwd()
        os.chdir('tools/yasuo/')
        subprocess.run(shlex.split(f'ruby yasuo.rb -f {cwd}/{path}/nmap_web_ip.xml -b all'))
        subprocess.run(shlex.split(f'ruby yasuo.rb -f {cwd}/{path}/nmap_web_domain.xml -b all'))
        os.chdir(cwd)
    if scan_type == 5:
        print("\033[91mRunning vulnerability scan on webapp ports\033[0m")
        cwd = os.getcwd()
        os.chdir('tools/yasuo/')
        subprocess.run(shlex.split(f'ruby yasuo.rb -f {cwd}/{path}/nmap_web_ip.xml -b all'))
        os.chdir(cwd)
    else:
        print("\033[91mRunning vulnerability scan on subdomains on webapp ports\033[0m")
        cwd = os.getcwd()
        os.chdir('tools/yasuo/')
        subprocess.run(shlex.split(f'ruby yasuo.rb -f {cwd}/{path}/nmap_web.xml -b all'))
        os.chdir(cwd)

def yasuo_all(path,ip,subnetmask,scan_type):
    splitter()
    if scan_type == 3:
        print("\033[91mRunning vulnerability scan on all ports\033[0m")
        cwd = os.getcwd()
        os.chdir('tools/yasuo/')
        subprocess.run(shlex.split(f'ruby yasuo.rb -f {cwd}/{path}/nmap-full-scan.xml -b all'))
        os.chdir(cwd)
    elif scan_type == 5:
        print(f"\033[91mRunning vulnerability scan on {ip}/{subnetmask} on all ports\033[0m")
        cwd = os.getcwd()
        os.chdir('tools/yasuo/')
        subprocess.run(shlex.split(f'sudo ruby yasuo.rb -r {ip}/{subnetmask} -A -b all'))
        os.chdir(cwd)

def linkfinder(domain,path,file_input_domain,scan_type):
    splitter()
    if scan_type == 3:
        print("\033[91mSearching for links\033[0m")
        subprocess.run(shlex.split(f'tools/LinkFinder/linkfinder.py -i {file_input_domain} -o {path}/links.html'))
    else:
        print("\033[91mSearching for links\033[0m")
        subprocess.run(shlex.split(f'tools/LinkFinder/linkfinder.py -i http://{domain} -o {path}/links.html'))

def nikto(path,file_input_domain,scan_type):
    splitter()
    if scan_type == 3:
        print("\033[91mRunning webapp scan (SSL)\033[0m")
        subprocess.run(shlex.split(f'nikto -h {file_input_domain} -ssl -output {path}/nikto-ssl.txt'))
        print("\033[91mRunning webapp scan (NO SSL)\033[0m")
        subprocess.run(shlex.split(f'nikto -h {file_input_domain} -nossl -output {path}/nikto-nossl.txt'))
    if scan_type == 5:
        print("\033[91mRunning webapp scan\033[0m")
        subprocess.run(shlex.split(f'nikto -h {path}/hosts_web_ip.txt -output {path}/nikto_web_ip.txt'))
    else:
        print("\033[91mRunning webapp scan\033[0m")
        subprocess.run(shlex.split(f'nikto -h {path}/amass.txt -output {path}/nikto_all.txt'))

def gobuster(domain,path):
    splitter()
    print("\033[91mBruteforcing directories\033[0m")
    subprocess.run(shlex.split(f'gobuster dir -u http://{domain}/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o {path}/gobuster'))

def nmap_subdomains(path):
    #Run Nmap for subdomain list
    splitter()
    print("\033[91mRunning port scan on all found subdomains\033[0m")
    subprocess.run(shlex.split(f'nmap -T4 -p- --open -vv -iL {path}/amass.txt -oA {path}/nmap_subdomains'))

def whatcms(domain):
    splitter()
    print("\033[91mRunning Whatcms to check CMS\033[0m")
    subprocess.run(shlex.split(f'tools/whatcms.sh {domain}'))

def nmapautomator(ip,path,nmapautomator_fast,nmapautomator_full,nmapautomator_vuln,nmapautomator_recon):
    splitter()
    if nmapautomator_fast == True:
        #Run fast port scan on IP
        subprocess.run(shlex.split(f'tools/nmapAutomator/nmapAutomator.sh {ip} Port -o {path}'))
    elif nmapautomator_full == True:
        #Run full port & script scan on IP
        subprocess.run(shlex.split(f'tools/nmapAutomator/nmapAutomator.sh {ip} Full -o {path}'))
    elif nmapautomator_vuln == True:
        #Run Vuln scan on IP
        subprocess.run(shlex.split(f'tools/nmapAutomator/nmapAutomator.sh {ip} Vulns -o {path}'))
    elif nmapautomator_recon == True:
        print("\033[91mNmapAutomator Recon mode\033[0m")
        subprocess.run(shlex.split(f'tools/nmapAutomator/nmapAutomator.sh {ip} Recon -o {path}'))

def webtech(ip):
    splitter()
    print("\033[91mRunning Webtech to identify web technologies\033[0m")
    wt = webtech.WebTech(options={'rua': True})

    # scan a single website
    try:
        report = wt.start_from_url('http://{ip}')
        print(report)
    except webtech.utils.ConnectionException:
        print("Connection error")

    try:
        report = wt.start_from_url('https://{ip}')
        print(report)
    except webtech.utils.ConnectionException:
        print("Connection error")

# NMAP OUTPUT PARSER

def nmapparser(path):
    #parse output
    os.system(f'tools/nmap-parse-output/nmap-parse-output {path}/nmap_web_ip.xml hosts > {path}/hosts_web_ip.txt')


# UPDATE FUNCTION

def update():
    subprocess.run(shlex.split('sudo apt update'))
    subprocess.run(shlex.split('sudo apt-get install nmap gobuster subfinder nikto -y'))
    os.chdir('tools/wafw00f/')
    subprocess.run(shlex.split('git pull --rebase --autostash'))
    os.chdir('../SubDomainizer/')
    subprocess.run(shlex.split('git pull --rebase --autostash'))
    os.chdir('../')
    subprocess.run(shlex.split('wget https://github.com/OWASP/Amass/releases/download/v3.20.0/amass_linux_amd64.zip'))
    subprocess.run(shlex.split('unzip amass_linux_amd64.zip'))
    subprocess.run(shlex.split('rm amass_linux_amd64.zip'))
    #os.chdir('GitDorker/')
    #subprocess.run(shlex.split('git pull --rebase --autostash'))
    #os.chdir('../')
    os.chdir('wig/')
    subprocess.run(shlex.split('git pull --rebase --autostash'))
    subprocess.run(shlex.split('python3 setup.py install'))
    os.chdir('../LinkFinder/')
    subprocess.run(shlex.split('git pull --rebase --autostash')) 
    os.chdir('../testssl.sh/')
    subprocess.run(shlex.split('git pull --rebase --autostash'))
    os.chdir('../yasuo/')
    subprocess.run(shlex.split('git pull --rebase --autostash'))
    os.chdir('../nmapAutomator/')
    subprocess.run(shlex.split('wget https://raw.githubusercontent.com/21y4d/nmapAutomator/master/nmapAutomator.sh'))

    splitter()
    print(f"\033[91mEverything is up to date now!\033[0m")

def install():
    subprocess.run(shlex.split('sudo apt update'))

    #install nmap, gobuster, subfinder and nikto
    subprocess.run(shlex.split('sudo apt-get install nmap gobuster subfinder nikto -y'))
    
    #setup tools directory
    try:
        os.mkdir('tools')
    except:
        print("Tools directory already exists! Try the update function")
    
    #setup wafw00f
    os.chdir('tools/')
    subprocess.run(shlex.split('git clone https://github.com/EnableSecurity/wafw00f.git'))
    os.chdir('wafw00f/')
    subprocess.run(shlex.split('python3 setup.py install'))

    #setup subdomainizer
    os.chdir('../')
    subprocess.run(shlex.split('git clone https://github.com/nsonaniya2010/SubDomainizer.git'))
    os.chdir('SubDomainizer/')
    subprocess.run(shlex.split('pip3 install -r requirements.txt'))

    #setup amass
    os.chdir('../') 
    subprocess.run(shlex.split('wget https://github.com/OWASP/Amass/releases/download/v3.20.0/amass_linux_amd64.zip'))
    subprocess.run(shlex.split('unzip amass_linux_amd64.zip'))
    subprocess.run(shlex.split('rm amass_linux_amd64.zip'))
    
    #setup GitDorker (not sure if GitDorker is still maintained)
    #subprocess.run(shlex.split('git clone https://github.com/obheda12/GitDorker.git'))
    #os.chdir('GitDorker/')
    #subprocess.run(shlex.split('pip3 install -r requirements.txt'))
    #print("Create a personal GitHub access token here: https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token")
    #os.chdir('../')

    #setup wig
    subprocess.run(shlex.split('git clone https://github.com/jekyc/wig.git'))
    os.chdir('wig/')
    subprocess.run(shlex.split('python3 setup.py install')) 

    #setup linkfinder
    subprocess.run(shlex.split('git clone https://github.com/GerbenJavado/LinkFinder.git')) 
    os.chdir('LinkFinder/')
    subprocess.run(shlex.split('pip3 install -r requirements.txt'))
    subprocess.run(shlex.split('python setup.py install'))
    os.chdir('../')

    #setup testssl
    subprocess.run(shlex.split('git clone --depth 1 https://github.com/drwetter/testssl.sh.git'))
    
    #setup yasuo
    subprocess.run(shlex.split('git clone https://github.com/0xsauby/yasuo.git'))

    #setup nmapAutomator
    os.mkdir('nmapAutomator/')
    os.chdir('nmapAutomator')
    subprocess.run(shlex.split('wget https://raw.githubusercontent.com/21y4d/nmapAutomator/master/nmapAutomator.sh'))

    splitter()
    print(f"\033[91mEverything is installed now!\033[0m")

menu()
