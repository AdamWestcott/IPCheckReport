import csv
import requests
from datetime import time, datetime
from pathlib import Path
import ApiKeys
virus_total_url = "https://www.virustotal.com/api/v3/ip_addresses/"

virus_total_headers = {
    "accept": "application/json",
    "x-apikey": ApiKeys.VirusTotalAPIKey
}

params = {}
ips = []

CSV_DATA = []

def csv_input():
    with open(input('Please enter the location of the CSV/Txt file containing Domains and IP Addresses: '),'r', encoding="utf8") as ip_file:
        ips.clear()
        reader = csv.reader(ip_file)
        for row in reader:
            ips.append(str(row[0]))

downloads_path = str(Path.home() / "Downloads")
#file_path = input('Please enter name for CSV export: ')
with open(downloads_path + '/VirusTotalCheck.csv', 'w', encoding="utf-8", newline='') as file:
    writer = csv.writer(file)
    ROW = []
    dataframeRow = 0
    ROW.append("IP Address")
    ROW.append("Virus Total: WhoIs")
    ROW.append("Virus Total: Tags")
    ROW.append("Virus Total: Country")
    ROW.append("Virus Total: Last Analysis Date")
    ROW.append("Virus Total: Last AS Owner")
    ROW.append("Virus Total: Last Analysis Stats")
    ROW.append("Virus Total: ASN")
    ROW.append("Virus Total: WhoIs Date")
    ROW.append("Virus Total: Reputation")
    ROW.append("Virus Total: bkav")
    ROW.append("Virus Total: CMC Threat Intelligence")
    ROW.append("Virus Total: Snort IP sample list")
    ROW.append("Virus Total: 0xSI f33d")
    ROW.append("Virus Total: ViriBack")
    ROW.append("Virus Total: PhishLabs")
    ROW.append("Virus Total: K7AntiVirus")
    ROW.append("Virus Total: CINS Army")
    ROW.append("Virus Total: Quttera")
    ROW.append("Virus Total: PrecisionSec")
    ROW.append("Virus Total: OpenPhish")
    ROW.append("Virus Total: VX Vault")
    ROW.append("Virus Total: ADMINUSLabs")
    ROW.append("Virus Total: Scantitan")
    ROW.append("Virus Total: AlienVault")
    ROW.append("Virus Total: Sophos")
    ROW.append("Virus Total: Phishtank")
    ROW.append("Virus Total: ESTsecurity")
    ROW.append("Virus Total: SecureBrain")
    ROW.append("Virus Total: Spam404")
    ROW.append("Virus Total: CRDF")
    ROW.append("Virus Total: Fortinet")
    ROW.append("Virus Total: alphaMountain")
    ROW.append("Virus Total: Lionic")
    ROW.append("Virus Total: Cyble")
    ROW.append("Virus Total: Seclookup")
    ROW.append("Virus Total: Xcitium Verdict Cloud")
    ROW.append("Virus Total: Google Safebrowsing")
    ROW.append("Virus Total: SafeToOpen")
    ROW.append("Virus Total: ArcSight Threat Intelligence")
    ROW.append("Virus Total: Cyan")
    ROW.append("Virus Total: Juniper Networks")
    ROW.append("Virus Total: Heimdal Security")
    ROW.append("Virus Total: AutoShun")
    ROW.append("Virus Total: Trustwave")
    ROW.append("Virus Total: AICC")
    ROW.append("Virus Total: CyRadar")
    ROW.append("Virus Total: Dr Web")
    ROW.append("Virus Total: Emsisoft")
    ROW.append("Virus Total: Abusix")
    ROW.append("Virus Total: Webroot")
    ROW.append("Virus Total: Avira")
    ROW.append("Virus Total: securolytics")
    ROW.append("Virus Total: Antiy AVL")
    ROW.append("Virus Total: AlphaSOC" )
    ROW.append("Virus Total: Acronis")
    ROW.append("Virus Total: Quick Heal")
    ROW.append("Virus Total: URLQuery")
    ROW.append("Virus Total: Viettel Threat Intelligence")
    ROW.append("Virus Total: DNS8")
    ROW.append("Virus Total: benkow")
    ROW.append("Virus Total: EmergingThreats")
    ROW.append("Virus Total: Chong Lua Dao")
    ROW.append("Virus Total: Yandex Safebrowsing")
    ROW.append("Virus Total: Lumu")
    ROW.append("Virus Total: zvelo")
    ROW.append("Virus Total: Kaspersky")
    ROW.append("Virus Total: Segasec")
    ROW.append("Virus Total: SiteCheck")
    ROW.append("Virus Total: desenmascara")
    ROW.append("Virus Total: CrowdSec")
    ROW.append("Virus Total: Cluster25")
    ROW.append("Virus Total: SOCRadar")
    ROW.append("Virus Total: URLhaus")
    ROW.append("Virus Total: PREBYTES")
    ROW.append("Virus Total: StopForumSpam")
    ROW.append("Virus Total: Blueliv")
    ROW.append("Virus Total: Netcraft")
    ROW.append("Virus Total: ZeroCERT")
    ROW.append("Virus Total: Phishing Database")
    ROW.append("Virus Total: MalwarePatrol")
    ROW.append("Virus Total: IPsum")
    ROW.append("Virus Total: Malwared")
    ROW.append("Virus Total: BitDefender")
    ROW.append("Virus Total: GreenSnow")
    ROW.append("Virus Total: G Data")
    ROW.append("Virus Total: VIPRE")
    ROW.append("Virus Total: SCUMWARE")
    ROW.append("Virus Total: PhishFort")
    ROW.append("Virus Total: malwares URL checker")
    ROW.append("Virus Total: Forcepoint ThreatSeeker")
    ROW.append("Virus Total: Criminal IP")
    ROW.append("Virus Total: Certego")
    ROW.append("Virus Total: ESET")
    ROW.append("Virus Total: Threatsourcing")
    ROW.append("Virus Total: ThreatHive")
    ROW.append("Virus Total: Bfore")
    ROW.append("Virus Total: Last Modification Date")
    ROW.append("Virus Total: Regional Internet Registry")
    ROW.append("Virus Total: Regional Continent")
    ROW.append("Virus Total: Total Harmless")
    ROW.append("Virus Total: Total Suspicous")
    ROW.append("Virus Total: Total Malicous")
    ROW.append("Virus Total: Total Undetected")
    ROW.append("Virus Total: Total Timeout")
    ROW.append("Virus Total: Total Score")
    ROW.append("Date & Time")
    CSV_DATA.append(ROW)
    ROW = []

    #pages = int(input("How many Pages will be input? (A Page consits of 100 sites) "))
    pages = 10
    thisdict = {}
    NumberOfAccounts =0
    sitehitlist =[]
    sitechecklist = []
    csv_input()
    for ip in ips:
        time = datetime.now().isoformat()
        ROW.append(str(ip))
        try:
            virus_total_response = requests.get(virus_total_url+str(ip), headers=virus_total_headers)
            virus_total_json = virus_total_response.json()
            virus_total_data = virus_total_json["data"]
            print(virus_total_data)
        except:
            print("Ip Not Found")

        virus_total_attributes = virus_total_data["attributes"]
        try:
            virus_total_whois = virus_total_attributes["whois"]
        except:
            virus_total_whois = "Not Found"
        try:
            virus_total_analysis_stats = virus_total_attributes["last_analysis_stats"]
        except:
            virus_total_analysis_stats = "Not Found"
        try:
            virus_total_tags = virus_total_attributes["tags"]
        except:
            virus_total_tags = "Not Found"
        try:
            virus_total_country = virus_total_attributes["country"]
        except:
            virus_total_country = "Not Found"
        try:
            virus_total_last_analysis_date = virus_total_attributes["last_analysis_date"]
            virus_total_last_analysis_date = datetime.utcfromtimestamp(virus_total_last_analysis_date).strftime('%Y-%m-%d %H:%M:%S')
        except:
            virus_total_last_analysis_date = "Not Found"
        try:
            virus_total_last_as_owner = virus_total_attributes["as_owner"]
        except:
            virus_total_last_as_owner = "Not Found"
        try:
            virus_total_last_analysis_stats = virus_total_attributes["last_analysis_stats"]
        except:
            virus_total_last_analysis_stats = "Not Found"
        try:
            virus_total_asn = virus_total_attributes["asn"]
        except:
            virus_total_asn = "Not Found"
        try:
            virus_total_whois_date= virus_total_attributes["whois_date"]
            virus_total_whois_date = datetime.utcfromtimestamp(virus_total_whois_date).strftime('%Y-%m-%d %H:%M:%S')
        except:
            virus_total_whois_date = "Not Found"
        try:
            virus_total_reputation= virus_total_attributes["reputation"]
        except:
            virus_total_reputation = "Not Found"
        try:
            virus_total_last_analysis_results= virus_total_attributes["last_analysis_results"]

            try:
                virus_total_bkav= virus_total_last_analysis_results["Bkav"]
            except:
                virus_total_bkav = "Not Found"

            try:
                virus_total_CMC_Threat_Intelligence= virus_total_last_analysis_results["CMC Threat Intelligence"]
            except:
                virus_total_CMC_Threat_Intelligence = "Not Found"
            
            try:
                virus_total_Snort_IP_sample_list= virus_total_last_analysis_results["Snort IP sample list"]
            except:
                virus_total_Snort_IP_sample_list = "Not Found"
            
            try:
                virus_total_0xSI_f33d= virus_total_last_analysis_results["0xSI_f33d"]
            except:
                virus_total_0xSI_f33d = "Not Found"

            try:
                virus_total_ViriBack= virus_total_last_analysis_results["ViriBack"]
            except:
                virus_total_ViriBack = "Not Found"

            try:
                virus_total_PhishLabs= virus_total_last_analysis_results["PhishLabs"]
            except:
                virus_total_PhishLabs = "Not Found"
            
            try:
                virus_total_K7AntiVirus= virus_total_last_analysis_results["K7AntiVirus"]
            except:
                virus_total_K7AntiVirus = "Not Found"

            try:
                virus_total_CINS_Army= virus_total_last_analysis_results["CINS Army"]
            except:
                virus_total_CINS_Army = "Not Found"
            
            try:
                virus_total_Quttera= virus_total_last_analysis_results["Quttera"]
            except:
                virus_total_Quttera = "Not Found"
            
            try:
                virus_total_PrecisionSec= virus_total_last_analysis_results["PrecisionSec"]
            except:
                virus_total_PrecisionSec = "Not Found"
            
            try:
                virus_total_OpenPhish= virus_total_last_analysis_results["OpenPhish"]
            except:
                virus_total_OpenPhish = "Not Found"
            
            try:
                virus_total_VX_Vault= virus_total_last_analysis_results["VX Vault"]
            except:
                virus_total_VX_Vault = "Not Found"
            
            try:
                virus_total_ADMINUSLabs= virus_total_last_analysis_results["ADMINUSLabs"]
            except:
                virus_total_ADMINUSLabs = "Not Found"
            
            try:
                virus_total_Scantitan= virus_total_last_analysis_results["Scantitan"]
            except:
                virus_total_Scantitan = "Not Found"

            try:
                virus_total_AlienVault= virus_total_last_analysis_results["AlienVault"]
            except:
                virus_total_AlienVault = "Not Found"
            
            try:
                virus_total_Sophos= virus_total_last_analysis_results["Sophos"]
            except:
                virus_total_Sophos = "Not Found"
            
            try:
                virus_total_Phishtank= virus_total_last_analysis_results["Phishtank"]
            except:
                virus_total_Phishtank = "Not Found"

            try:
                virus_total_ESTsecurity= virus_total_last_analysis_results["ESTsecurity"]
            except:
                virus_total_ESTsecurity = "Not Found"
            
            try:
                virus_total_SecureBrain= virus_total_last_analysis_results["SecureBrain"]
            except:
                virus_total_SecureBrain = "Not Found"

            try:
                virus_total_Spam404= virus_total_last_analysis_results["Spam404"]
            except:
                virus_total_Spam404 = "Not Found"
            
            try:
                virus_total_CRDF= virus_total_last_analysis_results["CRDF"]
            except:
                virus_total_CRDF = "Not Found"
            
            try:
                virus_total_Fortinet= virus_total_last_analysis_results["Fortinet"]
            except:
                virus_total_Fortinet = "Not Found"
            
            try:
                virus_total_alphaMountain= virus_total_last_analysis_results["alphaMountain.ai"]
            except:
                virus_total_alphaMountain = "Not Found"
            
            try:
                virus_total_Lionic= virus_total_last_analysis_results["Lionic"]
            except:
                virus_total_Lionic = "Not Found"
            
            try:
                virus_total_Cyble= virus_total_last_analysis_results["Cyble"]
            except:
                virus_total_Cyble = "Not Found"
            
            try:
                virus_total_Seclookup= virus_total_last_analysis_results["Seclookup"]
            except:
                virus_total_Seclookup = "Not Found"
            
            try:
                virus_total_Xcitium_Verdict_Cloud= virus_total_last_analysis_results["Xcitium Verdict Cloud"]
            except:
                virus_total_Xcitium_Verdict_Cloud = "Not Found"
            
            try:
                virus_total_Google_Safebrowsing= virus_total_last_analysis_results["Google Safebrowsing"]
            except:
                virus_total_Google_Safebrowsing = "Not Found"
            
            try:
                virus_total_SafeToOpen = virus_total_last_analysis_results["SafeToOpen"]
            except:
                virus_total_SafeToOpen = "Not Found"
            
            try:
                virus_total_ArcSight_Threat_Intelligence = virus_total_last_analysis_results["ArcSight Threat Intelligence"]
            except:
                virus_total_ArcSight_Threat_Intelligence = "Not Found"
            
            try:
                virus_total_Cyan = virus_total_last_analysis_results["Cyan"]
            except:
                virus_total_Cyan = "Not Found"
            
            try:
                virus_total_Juniper_Networks = virus_total_last_analysis_results["Juniper Networks"]
            except:
                virus_total_Juniper_Networks = "Not Found"
            
            try:
                virus_total_Heimdal_Security = virus_total_last_analysis_results["Heimdal Security"]
            except:
                virus_total_Heimdal_Security = "Not Found"
            
            try:
                virus_total_AutoShun = virus_total_last_analysis_results["AutoShun"]
            except:
                virus_total_AutoShun = "Not Found"
            
            try:
                virus_total_Trustwave = virus_total_last_analysis_results["Trustwave"]
            except:
                virus_total_Trustwave = "Not Found"
            
            try:
                virus_total_AICC = virus_total_last_analysis_results["AICC (MONITORAPP)"]
            except:
                virus_total_AICC = "Not Found"
            
            try:
                virus_total_CyRadar = virus_total_last_analysis_results["CyRadar"]
            except:
                virus_total_CyRadar = "Not Found"
            
            try:
                virus_total_Dr_Web = virus_total_last_analysis_results["Dr.Web"]
            except:
                virus_total_Dr_Web = "Not Found"
            
            try:
                virus_total_Emsisoft = virus_total_last_analysis_results["Emsisoft"]
            except:
                virus_total_Emsisoft = "Not Found"
            
            try:
                virus_total_Abusix = virus_total_last_analysis_results["Abusix"]
            except:
                virus_total_Abusix = "Not Found"

            try:
                virus_total_Webroot = virus_total_last_analysis_results["Webroot"]
            except:
                virus_total_Webroot = "Not Found"
            
            try:
                virus_total_Avira= virus_total_last_analysis_results["Avira"]
            except:
                virus_total_Avira = "Not Found"
            
            try:
                virus_total_securolytics= virus_total_last_analysis_results["securolytics"]
            except:
                virus_total_securolytics = "Not Found"
            
            try:
                virus_total_Antiy_AVL = virus_total_last_analysis_results["Antiy-AVL"]
            except:
                virus_total_Antiy_AVL = "Not Found"
            
            try:
                virus_total_AlphaSOC = virus_total_last_analysis_results["AlphaSOC"]
            except:
                virus_total_AlphaSOC = "Not Found"
            
            try:
                virus_total_Acronis = virus_total_last_analysis_results["Acronis"]
            except:
                virus_total_Acronis = "Not Found"
            
            try:
                virus_total_Quick_Heal = virus_total_last_analysis_results["Quick Heal"]
            except:
                virus_total_Quick_Heal = "Not Found"
            
            try:
                virus_total_URLQuery = virus_total_last_analysis_results["URLQuery"]
            except:
                virus_total_URLQuery = "Not Found"

            try:
                virus_total_Viettel_Threat_Intelligence = virus_total_last_analysis_results["Viettel Threat Intelligence"]
            except:
                virus_total_Viettel_Threat_Intelligence = "Not Found"
            
            try:
                virus_total_DNS8 = virus_total_last_analysis_results["DNS8"]
            except:
                virus_total_DNS8 = "Not Found"
            
            try:
                virus_total_benkow = virus_total_last_analysis_results["benkow.cc"]
            except:
                virus_total_benkow = "Not Found"
            
            try:
                virus_total_EmergingThreats = virus_total_last_analysis_results["EmergingThreats"]
            except:
                virus_total_EmergingThreats = "Not Found"
            
            try:
                virus_total_Chong_Lua_Dao = virus_total_last_analysis_results["Chong Lua Dao"]
            except:
                virus_total_Chong_Lua_Dao = "Not Found"
            
            try:
                virus_total_Yandex_Safebrowsing = virus_total_last_analysis_results["Yandex Safebrowsing"]
            except:
                virus_total_Yandex_Safebrowsing = "Not Found"
            
            try:
                virus_total_Lumu = virus_total_last_analysis_results["Lumu"]
            except:
                virus_total_Lumu = "Not Found"
            
            try:
                virus_total_zvelo = virus_total_last_analysis_results["zvelo"]
            except:
                virus_total_zvelo = "Not Found"
            
            try:
                virus_total_Kaspersky = virus_total_last_analysis_results["Kaspersky"]
            except:
                virus_total_Kaspersky = "Not Found"
            
            try:
                virus_total_Segasec = virus_total_last_analysis_results["Segasec"]
            except:
                virus_total_Segasec = "Not Found"
            
            try:
                virus_total_Sucuri_SiteCheck = virus_total_last_analysis_results["Sucuri SiteCheck"]
            except:
                virus_total_Sucuri_SiteCheck = "Not Found"
            
            try:
                virus_total_Sucuri_desenmascara = virus_total_last_analysis_results["desenmascara.me"]
            except:
                virus_total_Sucuri_desenmascara = "Not Found"
            
            try:
                virus_total_Sucuri_CrowdSec = virus_total_last_analysis_results["CrowdSec"]
            except:
                virus_total_Sucuri_CrowdSec = "Not Found"
            
            try:
                virus_total_Sucuri_Cluster25 = virus_total_last_analysis_results["Cluster25"]
            except:
                virus_total_Sucuri_Cluster25 = "Not Found"
            
            try:
                virus_total_Sucuri_SOCRadar = virus_total_last_analysis_results["SOCRadar"]
            except:
                virus_total_Sucuri_SOCRadar = "Not Found"
            
            try:
                virus_total_Sucuri_URLhaus = virus_total_last_analysis_results["URLhaus"]
            except:
                virus_total_Sucuri_URLhaus = "Not Found"
            
            try:
                virus_total_Sucuri_PREBYTES = virus_total_last_analysis_results["PREBYTES"]
            except:
                virus_total_Sucuri_PREBYTES = "Not Found"
            
            try:
                virus_total_Sucuri_StopForumSpam = virus_total_last_analysis_results["StopForumSpam"]
            except:
                virus_total_Sucuri_StopForumSpam = "Not Found"
            
            try:
                virus_total_Sucuri_Blueliv = virus_total_last_analysis_results["Blueliv"]
            except:
                virus_total_Sucuri_Blueliv = "Not Found"
            
            try:
                virus_total_Sucuri_Netcraft = virus_total_last_analysis_results["Netcraft"]
            except:
                virus_total_Sucuri_Netcraft = "Not Found"
            
            try:
                virus_total_Sucuri_ZeroCERT = virus_total_last_analysis_results["ZeroCERT"]
            except:
                virus_total_Sucuri_ZeroCERT = "Not Found"
            
            try:
                virus_total_Sucuri_Phishing_Database = virus_total_last_analysis_results["Phishing Database"]
            except:
                virus_total_Sucuri_Phishing_Database = "Not Found"
            
            try:
                virus_total_Sucuri_MalwarePatrol = virus_total_last_analysis_results["MalwarePatrol"]
            except:
                virus_total_Sucuri_MalwarePatrol = "Not Found"
            
            try:
                virus_total_Sucuri_IPsum = virus_total_last_analysis_results["IPsum"]
            except:
                virus_total_Sucuri_IPsum = "Not Found"
            
            try:
                virus_total_Sucuri_Malwared = virus_total_last_analysis_results["Malwared"]
            except:
                virus_total_Sucuri_Malwared = "Not Found"
            
            try:
                virus_total_Sucuri_BitDefender = virus_total_last_analysis_results["BitDefender"]
            except:
                virus_total_Sucuri_BitDefender = "Not Found"
            
            try:
                virus_total_Sucuri_GreenSnow = virus_total_last_analysis_results["GreenSnow"]
            except:
                virus_total_Sucuri_GreenSnow = "Not Found"
            
            try:
                virus_total_Sucuri_G_Data = virus_total_last_analysis_results["G-Data"]
            except:
                virus_total_Sucuri_G_Data = "Not Found"
            
            try:
                virus_total_Sucuri_VIPRE = virus_total_last_analysis_results["VIPRE"]
            except:
                virus_total_Sucuri_VIPRE = "Not Found"
            
            try:
                virus_total_Sucuri_SCUMWARE = virus_total_last_analysis_results["SCUMWARE.org"]
            except:
                virus_total_Sucuri_SCUMWARE = "Not Found"
            
            try:
                virus_total_Sucuri_PhishFort = virus_total_last_analysis_results["PhishFort"]
            except:
                virus_total_Sucuri_PhishFort = "Not Found"
            
            try:
                virus_total_Sucuri_malwares_URL_checker = virus_total_last_analysis_results["malwares.com URL checker"]
            except:
                virus_total_Sucuri_malwares_URL_checker = "Not Found"
            
            try:
                virus_total_Forcepoint_ThreatSeeker = virus_total_last_analysis_results["Forcepoint ThreatSeeker"]
            except:
                virus_total_Forcepoint_ThreatSeeker = "Not Found"
            
            try:
                virus_total_Criminal_IP = virus_total_last_analysis_results["Criminal IP"]
            except:
                virus_total_Criminal_IP = "Not Found"
            
            try:
                virus_total_Certego = virus_total_last_analysis_results["Certego"]
            except:
                virus_total_Certego = "Not Found"
            
            try:
                virus_total_ESET = virus_total_last_analysis_results["ESET"]
            except:
                virus_total_ESET = "Not Found"
            
            try:
                virus_total_Threatsourcing = virus_total_last_analysis_results["Threatsourcing"]
            except:
                virus_total_Threatsourcing = "Not Found"
            
            try:
                virus_total_ThreatHive = virus_total_last_analysis_results["ThreatHive"]
            except:
                virus_total_ThreatHive = "Not Found"
            
            try:
                virus_total_Bfore = virus_total_last_analysis_results["Bfore.Ai PreCrime"]
            except:
                virus_total_Bfore = "Not Found"

        except:
            virus_total_bkav = "Not Found"
            virus_total_CMC_Threat_Intelligence = "Not Found"
            virus_total_Snort_IP_sample_list = "Not Found"
            virus_total_0xSI_f33d = "Not Found"
            virus_total_ViriBack = "Not Found"
            virus_total_PhishLabs = "Not Found"
            virus_total_K7AntiVirus = "Not Found"
            virus_total_CINS_Army = "Not Found"
            virus_total_Quttera = "Not Found"
            virus_total_PrecisionSec = "Not Found"
            virus_total_OpenPhish = "Not Found"
            virus_total_VX_Vault = "Not Found"
            virus_total_ADMINUSLabs = "Not Found"
            virus_total_Scantitan = "Not Found"
            virus_total_AlienVault = "Not Found"
            virus_total_Sophos = "Not Found"
            virus_total_Phishtank = "Not Found"
            virus_total_ESTsecurity = "Not Found"
            virus_total_SecureBrain = "Not Found"
            virus_total_Spam404 = "Not Found"
            virus_total_CRDF = "Not Found"
            virus_total_Fortinet = "Not Found"
            virus_total_alphaMountain = "Not Found"
            virus_total_Lionic = "Not Found"
            virus_total_Cyble = "Not Found"
            virus_total_Seclookup = "Not Found"
            virus_total_Xcitium_Verdict_Cloud = "Not Found"
            virus_total_Google_Safebrowsing = "Not Found"
            virus_total_SafeToOpen = "Not Found"
            virus_total_ArcSight_Threat_Intelligence = "Not Found"
            virus_total_Cyan = "Not Found"
            virus_total_Juniper_Networks = "Not Found"
            virus_total_Heimdal_Security = "Not Found"
            virus_total_AutoShun = "Not Found"
            virus_total_Trustwave = "Not Found"
            virus_total_AICC = "Not Found"
            virus_total_CyRadar = "Not Found"
            virus_total_Dr_Web = "Not Found"
            virus_total_Emsisoft = "Not Found"
            virus_total_Abusix = "Not Found"
            virus_total_Webroot = "Not Found"
            virus_total_Avira = "Not Found"
            virus_total_securolytics = "Not Found"
            virus_total_Antiy_AVL = "Not Found"
            virus_total_AlphaSOC = "Not Found"
            virus_total_Acronis = "Not Found"
            virus_total_Quick_Heal = "Not Found"
            virus_total_URLQuery = "Not Found"
            virus_total_Viettel_Threat_Intelligence = "Not Found"
            virus_total_DNS8 = "Not Found"
            virus_total_benkow = "Not Found"
            virus_total_EmergingThreats = "Not Found"
            virus_total_Chong_Lua_Dao = "Not Found"
            virus_total_Yandex_Safebrowsing = "Not Found"
            virus_total_Lumu = "Not Found"
            virus_total_zvelo = "Not Found"
            virus_total_Kaspersky = "Not Found"
            virus_total_Segasec = "Not Found"
            virus_total_Sucuri_SiteCheck = "Not Found"
            virus_total_Sucuri_desenmascara = "Not Found"
            virus_total_Sucuri_CrowdSec = "Not Found"
            virus_total_Sucuri_Cluster25 = "Not Found"
            virus_total_Sucuri_SOCRadar = "Not Found"
            virus_total_Sucuri_URLhaus = "Not Found"
            virus_total_Sucuri_PREBYTES = "Not Found"
            virus_total_Sucuri_StopForumSpam = "Not Found"
            virus_total_Sucuri_Blueliv = "Not Found"
            virus_total_Sucuri_Netcraft = "Not Found"
            virus_total_Sucuri_ZeroCERT = "Not Found"
            virus_total_Sucuri_Phishing_Database = "Not Found"
            virus_total_Sucuri_MalwarePatrol = "Not Found"
            virus_total_Sucuri_IPsum = "Not Found"
            virus_total_Sucuri_Malwared = "Not Found"
            virus_total_Sucuri_BitDefender = "Not Found"
            virus_total_Sucuri_GreenSnow = "Not Found"
            virus_total_Sucuri_G_Data = "Not Found"
            virus_total_Sucuri_VIPRE = "Not Found"
            virus_total_Sucuri_SCUMWARE = "Not Found"
            virus_total_Sucuri_PhishFort = "Not Found"
            virus_total_Sucuri_malwares_URL_checker = "Not Found"
            virus_total_Forcepoint_ThreatSeeker = "Not Found"
            virus_total_Criminal_IP = "Not Found"
            virus_total_Certego = "Not Found"
            virus_total_ESET = "Not Found"
            virus_total_Threatsourcing = "Not Found"
            virus_total_ThreatHive = "Not Found"
            virus_total_Bfore = "Not Found"
            virus_total_Bfore = "Not Found"
        
        try:
            virus_total_last_modification_date = virus_total_attributes["last_modification_date"]
            virus_total_last_modification_date = datetime.utcfromtimestamp(virus_total_last_modification_date).strftime('%Y-%m-%d %H:%M:%S')
        except:
            virus_total_last_modification_date = "Not Found"
        
        try:
            virus_total_regional_internet_registry = virus_total_attributes["regional_internet_registry"]
        except:
            virus_total_regional_internet_registry = "Not Found"
        
        try:
            virus_total_regional_continent = virus_total_attributes["continent"]
        except:
            virus_total_regional_continent = "Not Found"
        
        virus_total_stats = virus_total_analysis_stats["harmless"] + virus_total_analysis_stats["malicious"] + virus_total_analysis_stats["suspicious"] + virus_total_analysis_stats["undetected"] + virus_total_analysis_stats["timeout"]
        virus_total_score =0
        if (virus_total_analysis_stats["harmless"] + virus_total_analysis_stats["undetected"] + virus_total_analysis_stats["timeout"]) == virus_total_stats:
            virus_total_score =0
        elif virus_total_analysis_stats["malicious"] != 0:
            virus_total_score = virus_total_analysis_stats["malicious"] + virus_total_analysis_stats["suspicious"] + virus_total_analysis_stats["undetected"]
        elif (virus_total_analysis_stats["suspicious"] + virus_total_analysis_stats["undetected"]) <= ((virus_total_stats/100)*20):
            virus_total_score = virus_total_analysis_stats["suspicious"] + virus_total_analysis_stats["undetected"]

        ROW.append(virus_total_whois)
        ROW.append(virus_total_tags)
        ROW.append(virus_total_country)
        ROW.append(virus_total_last_analysis_date)
        ROW.append(virus_total_last_as_owner)
        ROW.append(virus_total_last_analysis_stats)
        ROW.append(virus_total_asn)
        ROW.append(virus_total_whois_date)
        ROW.append(virus_total_reputation)
        ROW.append(virus_total_bkav)
        ROW.append(virus_total_CMC_Threat_Intelligence)
        ROW.append(virus_total_Snort_IP_sample_list)
        ROW.append(virus_total_0xSI_f33d)
        ROW.append(virus_total_ViriBack)
        ROW.append(virus_total_PhishLabs)
        ROW.append(virus_total_K7AntiVirus)
        ROW.append(virus_total_CINS_Army)
        ROW.append(virus_total_Quttera)
        ROW.append(virus_total_PrecisionSec)
        ROW.append(virus_total_OpenPhish)
        ROW.append(virus_total_VX_Vault)
        ROW.append(virus_total_ADMINUSLabs)
        ROW.append(virus_total_Scantitan)
        ROW.append(virus_total_AlienVault)
        ROW.append(virus_total_Sophos)
        ROW.append(virus_total_Phishtank)
        ROW.append(virus_total_ESTsecurity)
        ROW.append(virus_total_SecureBrain)
        ROW.append(virus_total_Spam404)
        ROW.append(virus_total_CRDF)
        ROW.append(virus_total_Fortinet)
        ROW.append(virus_total_alphaMountain)
        ROW.append(virus_total_Lionic)
        ROW.append(virus_total_Cyble)
        ROW.append(virus_total_Seclookup)
        ROW.append(virus_total_Xcitium_Verdict_Cloud)
        ROW.append(virus_total_Google_Safebrowsing)
        ROW.append(virus_total_SafeToOpen)
        ROW.append(virus_total_ArcSight_Threat_Intelligence)
        ROW.append(virus_total_Cyan)
        ROW.append(virus_total_Juniper_Networks)
        ROW.append(virus_total_Heimdal_Security)
        ROW.append(virus_total_AutoShun)
        ROW.append(virus_total_Trustwave)
        ROW.append(virus_total_AICC)
        ROW.append(virus_total_CyRadar)
        ROW.append(virus_total_Dr_Web)
        ROW.append(virus_total_Emsisoft)
        ROW.append(virus_total_Abusix)
        ROW.append(virus_total_Webroot)
        ROW.append(virus_total_Avira)
        ROW.append(virus_total_securolytics)
        ROW.append(virus_total_Antiy_AVL)
        ROW.append(virus_total_AlphaSOC)
        ROW.append(virus_total_Acronis)
        ROW.append(virus_total_Quick_Heal)
        ROW.append(virus_total_URLQuery)
        ROW.append(virus_total_Viettel_Threat_Intelligence)
        ROW.append(virus_total_DNS8)
        ROW.append(virus_total_benkow)
        ROW.append(virus_total_EmergingThreats)
        ROW.append(virus_total_Chong_Lua_Dao)
        ROW.append(virus_total_Yandex_Safebrowsing)
        ROW.append(virus_total_Lumu)
        ROW.append(virus_total_zvelo)
        ROW.append(virus_total_Kaspersky)
        ROW.append(virus_total_Segasec)
        ROW.append(virus_total_Sucuri_SiteCheck)
        ROW.append(virus_total_Sucuri_desenmascara)
        ROW.append(virus_total_Sucuri_CrowdSec)
        ROW.append(virus_total_Sucuri_Cluster25)
        ROW.append(virus_total_Sucuri_SOCRadar)
        ROW.append(virus_total_Sucuri_URLhaus)
        ROW.append(virus_total_Sucuri_PREBYTES)
        ROW.append(virus_total_Sucuri_StopForumSpam)
        ROW.append(virus_total_Sucuri_Blueliv)
        ROW.append(virus_total_Sucuri_Netcraft)
        ROW.append(virus_total_Sucuri_ZeroCERT)
        ROW.append(virus_total_Sucuri_Phishing_Database)
        ROW.append(virus_total_Sucuri_MalwarePatrol)
        ROW.append(virus_total_Sucuri_IPsum)
        ROW.append(virus_total_Sucuri_Malwared)
        ROW.append(virus_total_Sucuri_BitDefender)
        ROW.append(virus_total_Sucuri_GreenSnow)
        ROW.append(virus_total_Sucuri_G_Data)
        ROW.append(virus_total_Sucuri_VIPRE)
        ROW.append(virus_total_Sucuri_SCUMWARE)
        ROW.append(virus_total_Sucuri_PhishFort)
        ROW.append(virus_total_Sucuri_malwares_URL_checker)
        ROW.append(virus_total_Forcepoint_ThreatSeeker)
        ROW.append(virus_total_Criminal_IP)
        ROW.append(virus_total_Certego)
        ROW.append(virus_total_ESET)
        ROW.append(virus_total_Threatsourcing)
        ROW.append(virus_total_ThreatHive)
        ROW.append(virus_total_Bfore)
        ROW.append(virus_total_last_modification_date)
        ROW.append(virus_total_regional_internet_registry)
        ROW.append(virus_total_regional_continent)
        ROW.append(virus_total_analysis_stats["harmless"])
        ROW.append(virus_total_analysis_stats["suspicious"])
        ROW.append(virus_total_analysis_stats["malicious"])
        ROW.append(virus_total_analysis_stats["undetected"])
        ROW.append(virus_total_analysis_stats["timeout"])
        ROW.append(virus_total_score)  
        ROW.append(str(time))
        CSV_DATA.append(ROW)
        ROW = []      
    writer.writerows(CSV_DATA)
