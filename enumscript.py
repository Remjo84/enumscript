#!/usr/bin/env python

#######################################
#    Author: Rémy Cervenka            #
#    Linkedin: /in/rémy-cervenka/     #
#######################################

#import modules
import sys
import wafw00f
from time import sleep
import os
import subprocess
import shlex
import shutil


def print_ascii_art():
    print('\033[91m'+'\t\t\t\t\t\t'+'ENUMERATION TOOL'+'\033[0m')
    print('\033[6m'+'\t\t\t\t\t\t'+'STARTING UP'+'\033[0m')
    print('\33[32m'+ r'''

 *******                            **  **                                                                 **           **  
/**////**                          //  /**                                                                //  ******   /**  
/**   /**   *****   *****   ******  ** /**    *****  *******  **   ** **********     ******  *****  ****** **/**///** ******
/*******   **///** **///** **////**/** /**   **///**//**///**/**  /**//**//**//**   **////  **///**//**//*/**/**  /**///**/ 
/**///**  /*******/**  // /**   /**/** /**  /******* /**  /**/**  /** /** /** /**  //***** /**  //  /** / /**/******   /**  
/**  //** /**//// /**   **/**   /**/** /**  /**////  /**  /**/**  /** /** /** /**   /////**/**   ** /**   /**/**///    /**  
/**   //**//******//***** //****** /** ***  //****** ***  /**//****** *** /** /**   ****** //***** /***   /**/**       //** 
//     //  //////  /////   //////  // ///    ////// ///   //  ////// ///  //  //   //////   /////  ///    // //         //  

'''+'\33[0m')

def menu():
    print_ascii_art()
    print()

    choice = input("""
                      1: External passive scan
                      2: External active scan
                      3. External active scan for specific domains
                      4. Internal single host scan
                      5: Internal scan
                      6: Update
                      7: Exit

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
        sys.exit
    else:
        print("You must only select either 1, 2, 3, 4, 5, 6 or 7")
        print("Please try again")
        menu()

# Gather domain input  
def input_passive_domain():
    domain_passive = input('\033[91m'+'Enter domain name: '+'\033[0m')
    parent_dir_passive = "external_passive"
    path_passive_domain = os.path.join(parent_dir_passive, domain_passive)
    print(f'Working on gathering info on {domain_passive}')
    external_passive(domain_passive,path_passive_domain)
    #hier de functies aanroepen zoals de regel hierboven

def input_active_domain():
    domain_active = input('\033[91m'+'Enter domain name: '+'\033[0m')
    parent_dir_org = "external_active"
    path_active_domain = os.path.join(parent_dir_org, domain_active)
    print(f'Working on gathering info on {domain_active}')
    external_active(domain_active,path_active_domain)
    #hier de functies aanroepen zoals de regel hierboven

def input_active_domain_specific():
    file_input_domain = input('\033[91m'+'Enter domain file name: '+'\033[0m')
    file_input_ip = input('\033[91m'+'Enter ip-host file name: '+'\033[0m')
    project = input('\033[91m'+'Enter project name: '+'\033[0m')
    parent_dir_spec = ("external_specific/")
    path = os.path.join(parent_dir_spec, project)
    #path = (f"external_specific/{project}")

    print(f'Working on gathering domains from {file_input_domain} and {file_input_ip}')
    external_active_specific(file_input_domain,file_input_ip,path)
    #hier de functies aanroepen zoals de regel hierboven

def input_ip_single():
    ip_single = input('\033[91m'+'Enter a single IP-address, for example: 192.168.10.70: '+'\033[0m')
    parent_dir_internal_single = "internal_single"
    path_dir_internal_single = os.path.join(parent_dir_internal_single, ip_single)
    print(f'Working on gathering info on {ip_single}')

    internal_single(ip_single,path_dir_internal_single)
    #hier de functies aanroepen zoals de regel hierboven  

# Gather IP input  
def input_ip():
    ip = input('\033[91m'+'Enter IP subnet, for example: 192.168.10.0: '+'\033[0m')
    subnetmask = input('\033[91m'+'Enter subnet mask, for example: 8, 16 or 24: '+'\033[0m')
    parent_dir_ip = "internal"
    path_internal = os.path.join(parent_dir_ip, ip)
    print(f'Working on gathering info on {ip}/{subnetmask}')

    internal(ip,subnetmask,path_internal)
    #hier de functies aanroepen zoals de regel hierboven  

def mkdir(path_passive_domain):
    print('\033[91m'+'Sorting directories...'+'\033[0m')
    sleep(1)
    if os.path.exists(path_passive_domain):
        print('Directory already exists'+'\n'+'Using existing directory')
    else:
        print('Creating directory...')
        try:
            os.makedirs(path_passive_domain)
        except OSError:
            print('Creation of the directory failed...')
        else:
            print('Successfully created the directory!')

def mkdir(path_active_domain):
    print('\033[91m'+'Sorting directories...'+'\033[0m')
    sleep(1)
    if os.path.exists(path_active_domain):
        print('Directory already exists'+'\n'+'Using existing directory')
    else:
        print('Creating directory...')
        try:
            os.makedirs(path_active_domain)
        except Exception as e:
            print(e)
        else:
            print('Successfully created the directory!')

def mkdir(path):
    print('\033[91m'+'Sorting directories...'+'\033[0m')
    sleep(1)
    
    if os.path.exists(path):
        print(f'{path} directory already exists'+'\n'+'Using existing directory')   
    else:
        print('Creating directory...')
        try:
            os.makedirs(path)
        except Exception as e:
            print(e)
        else:
            print('Successfully created the directory!')
   
def mkdir(path_dir_internal_single):
    print('\033[91m'+'Sorting directories...'+'\033[0m')
    sleep(1)
    if os.path.exists(path_dir_internal_single):
        print('Directory already exists'+'\n'+'Using existing directory')
    else:
        print('Creating directory...')
        try:
            os.makedirs(path_dir_internal_single)
        except Exception as e:
            print(e)
        else:
            print('Successfully created the directory!')            

def mkdir(path_dir_internal):
    print('\033[91m'+'Sorting directories...'+'\033[0m')
    sleep(1)
    if os.path.exists(path_dir_internal):
        print('Directory already exists'+'\n'+'Using existing directory')
    else:
        print('Creating directory...')
        try:
            os.makedirs(path_dir_internal)
        except Exception as e:
            print(e)
        else:
            print('Successfully created the directory!')  

def external_passive(domain_passive,path_passive_domain):
    mkdir(path_passive_domain)
    #Run Wafw00f
    print("\033[91mChecking for WAF\033[0m")
    path = ("tools/wafw00f/wafw00f/main.py")
    args = ("-o")
    output = (f"{path_passive_domain}/wafw00f.txt")
    subprocess.run([sys.executable, path, domain_passive, args, output])

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Wig
    print("\033[91mRunning WebApp Information Gatherer\033[0m")
    subprocess.run(shlex.split(f'tools/wig/wig.py {domain_passive} -q --no_cache_load --no_cache_save -w {path_passive_domain}/wig'))

    print('\033[91m'+'-'*60+'\033[0m')
    print("\033[91mRunning Whatcms to check CMS\033[0m")
    subprocess.run(shlex.split(f'tools/whatcms.sh {domain_passive}'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run SubDomainizer
    print("\033[91mRunning SubDomainizer\033[0m")
    path = ("tools/SubDomainizer/SubDomainizer.py")
    args = ("-u")
    output = ("-o")
    outputdir = (f"{path_passive_domain}/subdomainizer")
    subprocess.run([sys.executable, path, args, domain_passive])

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Amass
    print("\033[91mRunning Amass to search for subdomains\033[0m")
    subprocess.run(shlex.split(f'tools/amass_linux_amd64/amass enum -d {domain_passive} -oA {path_passive_domain}/amass'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Subfinder
    print("\033[91mRunning Subfinder to find http subdomains\033[0m")
    subprocess.run(shlex.split(f'subfinder -d {domain_passive} |httpx - csp-probe -title -status'))

    #print('\033[91m'+'-'*60+'\033[0m')
    #Run GitDorker
    #print("\033[91mRunning GitHub enumeration\033[0m")
    #subprocess.run(shlex.split(f'tools/GitDorker/GitDorker.py -tf tools/GitDorker/token -q {domain_passive} -d tools/GitDorker/Dorks/alldorksv3 -o {path_passive_domain}/gitdorker'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Testssl
    print("\033[91mRunning SSL and Security Headers check\033[0m")
    subprocess.run(shlex.split(f'tools/testssl.sh/testssl.sh -oA {path_passive_domain}/testssl --append {domain_passive}'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Nmap shodan check
    print("\033[91mRunning Shodan port check via Nmap\033[0m")
    subprocess.run(shlex.split(f'nmap -sn -Pn -n --script shodan-api --script-args shodan-api.apikey=v4yHwIDvHonnAEf6IsimyDRacbvm4RY5 {domain_passive} -oA {path_passive_domain}/nmap_shodan_passive'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Nmap shodan check
    print("\033[91mRunning Shodan port check on subdomains via Nmap\033[0m")
    subprocess.run(shlex.split(f'nmap -sn -Pn -n --script shodan-api --script-args shodan-api.apikey=v4yHwIDvHonnAEf6IsimyDRacbvm4RY5 -iL {path_passive_domain}/amass.txt -oA {path_passive_domain}/nmap_shodan_passive_sub'))

def external_active(domain_active,path_active_domain):
    mkdir(path_active_domain)

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Amass
    print("\033[91mRunning Amass to search for subdomains\033[0m")
    subprocess.run(shlex.split(f'tools/amass_linux_amd64/amass enum -d {domain_active} -oA {path_active_domain}/amass'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Nmap
    print("\033[91mRunning port scan on web ports\033[0m")
    subprocess.run(shlex.split(f'nmap -p 80,8080,8000,8001,8008,443,8443,5000,5001 --open -iL {path_active_domain}/amass.txt -oA {path_active_domain}/nmap_web'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Yasuo
    print("\033[91mRunning vulnerability scan on subdomains on webapp ports\033[0m")
    cwd = os.getcwd()
    os.chdir('tools/yasuo/')
    subprocess.run(shlex.split(f'ruby yasuo.rb -f {cwd}/{path_active_domain}/nmap_web.xml -b all'))
    os.chdir(cwd)

    print('\033[91m'+'-'*60+'\033[0m')

    #parse output
    os.system(f'tools/nmap-parse-output/nmap-parse-output {path_active_domain}/nmap_web.xml hosts > {path_active_domain}/hosts_web.txt')

    #Run Wafw00f
    print("\033[91mChecking for WAF\033[0m")
    subprocess.run(shlex.split(f'tools/wafw00f/wafw00f/main.py -i {path_active_domain}/hosts_web.txt -o {path_active_domain}/wafw00f.txt'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run SubDomainizer
    print("\033[91mRunning SubDomainizer\033[0m")
    path = ("tools/SubDomainizer/SubDomainizer.py")
    args = ("-u")
    output = ("-o")
    outputdir = (f"{path_active_domain}/subdomainizer")
    subprocess.run([sys.executable, path, args, domain_active])

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Subfinder
    print("\033[91mRunning Subfinder to find http subdomains\033[0m")
    subprocess.run(shlex.split(f'subfinder -d {domain_active} |httpx - csp-probe -title -status'))


    print('\033[91m'+'-'*60+'\033[0m')
    #Run LinkFinder
    print("\033[91mSearching for links\033[0m")
    subprocess.run(shlex.split(f'tools/LinkFinder/linkfinder.py -i http://{domain_active} -o {path_active_domain}/links.html'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Testssl
    print("\033[91mRunning SSL and Security Headers check\033[0m")
    subprocess.run(shlex.split(f'tools/testssl.sh/testssl.sh -oA {path_active_domain}/testssl_check_all --append -iL {path_active_domain}/amass.txt'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Nikto
    print("\033[91mRunning webapp scan\033[0m")
    subprocess.run(shlex.split(f'nikto -h {path_active_domain}/amass.txt -output {path_active_domain}/nikto_all.txt'))

    #run WIG
    subprocess.run(shlex.split(f'tools/wig/wig.py -l {path_active_domain}/hosts_web.txt -q --no_cache_load --no_cache_save -w {path_active_domain}/wig'))

    print('\033[91m'+'-'*60+'\033[0m')
    print("\033[91mRunning Whatcms to check CMS\033[0m")
    subprocess.run(shlex.split(f'tools/whatcms.sh {domain_active}'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Gobuster
    print("\033[91mBruteforcing directories\033[0m")
    subprocess.run(shlex.split(f'gobuster dir -u http://{domain_active}/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o {path_active_domain}/gobuster'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Nmap
    print("\033[91mRunning port scan on all ports\033[0m")
    subprocess.run(shlex.split(f'nmap -p- --open -vv {domain_active} -oA {path_active_domain}/nmap'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Nmap for subdomain list
    print("\033[91mRunning port scan on all found subdomains\033[0m")
    subprocess.run(shlex.split(f'nmap -T4 -p- --open -vv -iL {path_active_domain}/amass.txt -oA {path_active_domain}/nmap_subdomains'))

def external_active_specific(file_input_domain,file_input_ip,path):
    mkdir(path)

    #Reading data from file_input_domain
    with open (file_input_domain) as fp:
    	domain_data = fp.read()

    with open (file_input_ip) as fp:
    	ip_data = fp.read()

    domain_data += "\n"
    domain_data += ip_data

    with open (f'{path}/combined-file.txt', 'w') as fp:
    	fp.write(domain_data)



    print('\033[91m'+'-'*60+'\033[0m')
    #Run Nmap
    print("\033[91mSearching for open web ports on IP addresses\033[0m")
    subprocess.run(shlex.split(f'nmap -p 80,8080,8000,8001,8008,443,4443,8443,5000,5001,9443 -sV --open -iL {file_input_ip} -oA {path}/nmap_web_ip'))
    #subprocess.run(shlex.split(f'nmap -p http* --open -sV -iL {file_input_ip} -oA {path}/nmap_web'))
    print('\033[91m'+'-'*60+'\033[0m')
    print("\033[91mSearching for open web ports on domain names\033[0m")
    subprocess.run(shlex.split(f'nmap -p 80,8080,8000,8001,8008,443,4443,8443,5000,5001,9443 -sV --open -iL {file_input_domain} -oA {path}/nmap_web_domain'))
    #subprocess.run(shlex.split(f'nmap -p http* --open -sV -iL {file_input_domain} -oA {path}/nmap_web_domain'))

    #parse output
    os.system(f'tools/nmap-parse-output/nmap-parse-output {path}/nmap_web_ip.xml hosts > {path}/hosts_web_ip.txt')


    print('\033[91m'+'-'*60+'\033[0m')
    #Run Wafw00f
    print("\033[91mChecking for WAF\033[0m")
    subprocess.run(shlex.split(f'tools/wafw00f/wafw00f/main.py -i {file_input_domain} -o {path}/wafw00f-domain.txt'))
    subprocess.run(shlex.split(f'tools/wafw00f/wafw00f/main.py -i {path}/hosts_web_ip.txt -o {path}/wafw00f-ip.txt'))

    print('\033[91m'+'-'*60+'\033[0m')
    #run WIG
    subprocess.run(shlex.split(f'tools/wig/wig.py -l {file_input_domain} -q --no_cache_load --no_cache_save -w {path}/wig-domain'))
    subprocess.run(shlex.split(f'tools/wig/wig.py -l {path}/hosts_web_ip.txt -q --no_cache_load --no_cache_save -w {path}/wig-domain'))


    print('\033[91m'+'-'*60+'\033[0m')
    #Run SubDomainizer
    print("\033[91mRunning SubDomainizer\033[0m")
    subprocess.run(shlex.split(f'tools/SubDomainizer/SubDomainizer.py -l {file_input_domain} -o {path}/subdomainizer_spec'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run LinkFinder
    print("\033[91mSearching for links\033[0m")
    subprocess.run(shlex.split(f'tools/LinkFinder/linkfinder.py -i {file_input_domain} -o {path}/links.html'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Testssl
    print("\033[91mRunning SSL and Security Headers check\033[0m")
    subprocess.run(shlex.split(f'tools/testssl.sh/testssl.sh -oA {path}/testssl --append -iL {file_input_domain}'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Nikto
    print("\033[91mRunning webapp scan (SSL)\033[0m")
    subprocess.run(shlex.split(f'nikto -h {file_input_domain} -ssl -output {path}/nikto-ssl.txt'))
    print("\033[91mRunning webapp scan (NO SSL)\033[0m")
    subprocess.run(shlex.split(f'nikto -h {file_input_domain} -nossl -output {path}/nikto-nossl.txt'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Yasuo on web ports
    print("\033[91mRunning vulnerability scan on webapp ports\033[0m")
    cwd = os.getcwd()
    os.chdir('tools/yasuo/')
    subprocess.run(shlex.split(f'ruby yasuo.rb -f {cwd}/{path}/nmap_web_ip.xml -b all'))
    subprocess.run(shlex.split(f'ruby yasuo.rb -f {cwd}/{path}/nmap_web_domain.xml -b all'))
    os.chdir(cwd)


    # print('\033[91m'+'-'*60+'\033[0m')
    # #Run Gobuster
    # print("\033[91mBruteforcing directories\033[0m")
    # subprocess.run(shlex.split(f'gobuster dir -u http://{domain_active_spec}/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o {domain_active_spec}/gobuster'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Nmap on all ports
    print(f"\033[91mRunning port scan on all ports\033[0m")
    subprocess.run(shlex.split(f'nmap -p- --open -vv -iL {path}/combined-file.txt -oA {path}/nmap-full-scan'))
    #subprocess.run(shlex.split(f'nmap -p- --open -vv -iL {file_input_domain} -oA {path}/nmap-domain'))

    #Run Yasuo on all ports
    print("\033[91mRunning vulnerability scan on all ports\033[0m")
    cwd = os.getcwd()
    os.chdir('tools/yasuo/')
    subprocess.run(shlex.split(f'ruby yasuo.rb -f {cwd}/{path}/nmap-full-scan.xml -b all'))
    os.chdir(cwd)

def internal_single(ip_single,path_dir_internal_single):
    mkdir(path_dir_internal_single)
    print('\033[91m'+'-'*60+'\033[0m')

    # #Run Nmap top 100 ports
    # print("\033[91mScanning top 100 ports\033[0m")
    # subprocess.run(shlex.split(f'nmap -p 0-1000 {ip_single} --open -oA {path_dir_internal_single}/nmap_top1000_internal'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run fast port scan on IP
    subprocess.run(shlex.split(f'tools/nmapAutomator/nmapAutomator.sh {ip_single} Port -o {path_dir_internal_single}'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run full port & script scan on IP
    subprocess.run(shlex.split(f'tools/nmapAutomator/nmapAutomator.sh {ip_single} Full -o {path_dir_internal_single}'))

    print('\033[91m'+'-'*60+'\033[0m')
    print("\033[91mRunning Webtech to identify web technologies\033[0m")
    subprocess.run(shlex.split(f'webtech -u http://{ip_single} --rua'))
    subprocess.run(shlex.split(f'webtech -u https://{ip_single} --rua'))


    print('\033[91m'+'-'*60+'\033[0m')
    print("\033[91mRunning Whatcms to check CMS\033[0m")
    subprocess.run(shlex.split(f'tools/whatcms.sh {ip_single}'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Vuln scan on IP
    subprocess.run(shlex.split(f'tools/nmapAutomator/nmapAutomator.sh {ip_single} Vulns -o {path_dir_internal_single}'))


    print("\033[91mNmapAutomator Recon mode\033[0m")
    subprocess.run(shlex.split(f'tools/nmapAutomator/nmapAutomator.sh {ip_single} Recon -o {path_dir_internal_single}'))

    # #Run Nmap
    # print("\033[91mRunning port scan on web ports\033[0m")
    # subprocess.run(shlex.split(f'nmap -p 80,8080,8000,8001,8008,443,8443,5000,5001 {ip_single} --open -oA {path_dir_internal_single}/nmap_web_internal'))


    # print('\033[91m'+'-'*60+'\033[0m')
    # print("\033[91mRunning WebApp Information Gatherer\033[0m")
    # subprocess.run(shlex.split(f'tools/wig/wig.py {ip_single} -q --no_cache_load --no_cache_save -w {path_dir_internal_single}/wig'))


    # print('\033[91m'+'-'*60+'\033[0m')
    # #Run quick Nmap on IP-range
    # print(f"\033[91mRunning fast port scan on {ip_single} on all ports\033[0m")
    # subprocess.run(shlex.split(f'nmap -p- {ip_single} -vv --open -oA {path_dir_internal_single}/nmap_full_scan_internal'))

    # print('\033[91m'+'-'*60+'\033[0m')
    # #Run quick Nmap on IP-range
    # print(f"\033[91mRunning intensive port scan on {ip_single} on all ports\033[0m")
    # subprocess.run(shlex.split(f'nmap -sC -sV -p- {ip_single} -vv --open -oA {path_dir_internal_single}/nmap_full_scan_internal_extra'))

    #print('\033[91m'+'-'*60+'\033[0m')
    ##Run Gobuster
    #print("\033[91mBruteforcing directories\033[0m")
    #subprocess.run(shlex.split(f'gobuster dir -u http://{ip_single}/ -w /usr/share/wordlists/dirb/common.txt -o {path_dir_internal_single}/gobuster'))
#
    #print('\033[91m'+'-'*60+'\033[0m')
    ## #Run Nikto
    #print("\033[91mRunning webapp scan\033[0m")
    #subprocess.run(shlex.split(f'nikto -h {ip_single} -output {path_dir_internal_single}/nikto_web_internal_single.txt'))


def internal(ip,subnetmask,path_dir_internal):
    mkdir(path_dir_internal)
    print('\033[91m'+'-'*60+'\033[0m')
    #Run Nmap
    print("\033[91mRunning port scan on web ports\033[0m")
    subprocess.run(shlex.split(f'nmap -p 80,8080,8000,8001,8008,443,8443,5000,5001 {ip}/{subnetmask} --open -oA {path_dir_internal}/nmap_web_internal'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run Yasuo
    print("\033[91mRunning vulnerability scan on subdomains on webapp ports\033[0m")
    cwd = os.getcwd()
    os.chdir('tools/yasuo/')
    subprocess.run(shlex.split(f'ruby yasuo.rb -f {cwd}/{path_dir_internal}/nmap_web_internal.xml -b all'))
    os.chdir(cwd)

    print('\033[91m'+'-'*60+'\033[0m')
    #Parse output
    print("\033[91mRunning WebApp Information Gatherer\033[0m")
    os.system(f'tools/nmap-parse-output/nmap-parse-output {path_dir_internal}/nmap_web_internal.xml hosts > {path_dir_internal}/hosts_web_internal.txt')

    #run WIG
    subprocess.run(shlex.split(f'tools/wig/wig.py -l {path_dir_internal}/hosts_web_internal.txt -q --no_cache_load --no_cache_save -w {path_dir_internal}/wig'))

    print('\033[91m'+'-'*60+'\033[0m')
    # #Run Nikto
    print("\033[91mRunning webapp scan\033[0m")
    subprocess.run(shlex.split(f'nikto -h {path_dir_internal}/hosts_web_internal.txt -output {path_dir_internal}/nikto_web_internal.txt'))

    print('\033[91m'+'-'*60+'\033[0m')
    #Run quick Nmap on IP-range
    print(f"\033[91mRunning port scan on {ip}/{subnetmask} on all ports\033[0m")
    subprocess.run(shlex.split(f'nmap -p- {ip}/{subnetmask} -vv --open -oA {path_dir_internal}/nmap_full_scan_internal'))


    print('\033[91m'+'-'*60+'\033[0m')
    #Run Yasuo all ports
    print(f"\033[91mRunning vulnerability scan on {ip}/{subnetmask} on all ports\033[0m")
    cwd = os.getcwd()
    os.chdir('tools/yasuo/')
    subprocess.run(shlex.split(f'sudo ruby yasuo.rb -r {ip}/{subnetmask} -A -b all'))
    os.chdir(cwd)



#functie voor het updaten van alle tools
def update():
    subprocess.run(shlex.split('sudo apt update'))
    subprocess.run(shlex.split('sudo apt-get install nmap gobuster subfinder nikto -y'))
    #cwd = os.getcwd()
    os.chdir('tools/wafw00f/')
    subprocess.run(shlex.split('git pull --rebase --autostash'))
    os.chdir('../SubDomainizer/')
    subprocess.run(shlex.split('git pull --rebase --autostash'))
    os.chdir('../amass_linux_amd64/')
    subprocess.run(shlex.split('git pull --rebase --autostash'))
    os.chdir('../GitDorker/')
    subprocess.run(shlex.split('git pull --rebase --autostash'))
    os.chdir('../wig/')
    subprocess.run(shlex.split('git pull --rebase --autostash'))
    subprocess.run(shlex.split('python3 setup.py install'))
    os.chdir('../LinkFinder/')
    subprocess.run(shlex.split('git pull --rebase --autostash')) 
    os.chdir('../testssl.sh/')
    subprocess.run(shlex.split('git pull --rebase --autostash'))
    os.chdir('../yasuo/')
    subprocess.run(shlex.split('git pull --rebase --autostash')) 

    print(f"\033[91mEverything is up to date now!\033[0m")


    menu()

#functie menu() aanroepen
menu()
