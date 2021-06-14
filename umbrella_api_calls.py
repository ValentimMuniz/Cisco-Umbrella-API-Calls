from tkinter import Toplevel,Menu,Label,Button,messagebox,filedialog,simpledialog,ttk,Text,Tk,END,Canvas,NW
from tkcalendar import Calendar
from PIL import ImageTk,Image
from collections import OrderedDict
from datetime import timedelta as td, datetime,timezone, tzinfo, date
import pandas as pd
from dateutil import tz
from csv import reader,DictReader
from unidecode import unidecode
import json
import requests,base64
import configparser
import sys
import os
import ipaddress
import webbrowser
from pathlib import Path 
import time
import threading
from time import sleep
import random


############################# Classe com as variáveis para tradução #############################
class globalV():
    manual = True
    texto_acesso_negadoTitulo_root = ""
    texto_acesso_negado_root = ""
    texto_label_linguagem_root = ""
    title_label_root = ""
    title_root = ""
    access_btn_root = ""
    firstTimeScript_message = ""
    firstTimeScript_message_title = ""
    firstTimeScript_ask_mgm_secret = ""
    firstTimeScript_ask_mgm_key = ""
    firstTimeScript_ask_investigate_key = ""
    firstTimeScript_ask_reporting_key = ""
    firstTimeScript_ask_reporting_secret = ""
    firstTimeScript_ask_orgID = ""
    firstTimeScript_ask_titles = ""
    firstTimeScript_empty_orgID = ""
    firstTimeScript_empty_orgID_title = ""
    firstTimeScript_empty_mgmg_key = ""
    firstTimeScript_empty_mgmg_key_title  = ""
    firstTimeScript_empty_secret_key = ""
    firstTimeScript_empty_secret_key_title = ""
    firstTimeScript_empty_reporting_key = ""
    firstTimeScript_empty_reporting_key_title = ""
    firstTimeScript_empty_reporting_secret_key = ""
    firstTimeScript_empty_reporting_secret_key_title = ""
    firstTimeScript_empty_investigate_key = ""
    firstTimeScript_empty_investigate_key_title = ""
    fileDiaglog_explorer = ""
    configuration_file_successfuly_saved = ""
    configuration_file_successfuly_saved_title = ""
    save_config_btn = ""
    configFile_title = ""
    send_btn = ""
    explore_csv_btn = ""
    label_csv_selected = ""
    label_choose_csv = ""
    csv_missing = ""
    csv_missing_title = ""
    csv_error_Destinations_log = ""
    csv_error_Sites_log = ""
    csv_error_InternalDomains_log = ""
    csv_error_InternalNetworks_log = ""
    wrong_csv_line = ""
    wrong_csv = ""
    wrong_csv_title = ""
    csv_already_registred = ""
    csv_already_registred_title = ""
    invalid_ip_log2 = ""
    invalid_ip_log1 = ""
    invalid_ip_message = ""
    invalid_ip__message_title = ""
    choose_valid_site = ""
    choose_valid_site_title = ""
    confirmation_site_assign = ""
    choose_valid_list = ""
    choose_valid_list_title = ""
    confirmation_list_assign = ""
    confirmation_title = ""
    destinationName_text_empty = ""
    destinationName_text_empty_title = ""
    destinationManual_destination_label = ""
    destinationManual_title_label = ""
    destinationManual_title = ""
    destinationManual_successfully_regitred = ""
    success_title = ""
    destinationManual_already_registred = ""
    destinationManual_destination_text = ""
    destinationManual_already_registred_title = ""
    destination_list_assign_label = ""
    destinationCSV_title_label = ""
    destinationCSV_title = ""
    destination_log = ""
    destination_successfully_registred = ""
    destination_successfully_registred_title = ""
    internalnetworks_site_assign_label = ""
    internalnetworks_title_label = ""
    internalnetworks_title = ""
    internalnetworks_log = ""
    internalnetworks_timereg = ""
    internalnetworks_successfully_registred = ""
    internalnetworks_successfully_registred_title = ""
    domainName_text_empty = ""
    domainName_text_empty_title = ""
    internaldomain_title_label = ""
    internaldomain_title = ""
    invalid_orgID_title = ""
    invalid_orgID_verify_email = ""
    invalid_orgID_default = ""
    invalid_mgmt_title_verify_email = "" 
    invalid_mgmt_verify_email = ""
    invalid_mgmt_default = ""
    empty_email_text = ""
    menu_exit = ""
    menu_configFile_title = "" 
    menu_configFile = ""
    menu_policy_components = ""
    menu_destinations_csv = ""
    menu_destinations_manual = ""
    menu_domain = ""
    menu_domain_csv = ""
    menu_domain_manual = ""
    menu_internalNetworks = ""
    menu_internalNetworks_csv = ""
    menu_sites = ""
    menu_sites_csv = ""
    menu_sites_manual = ""
    sites_successfully_registred_title = ""
    sites_successfully_registred = ""
    sites_log = ""
    sitesCSV_title = ""
    sitesCSV_title_label = ""
    siteManual_already_registred_title = ""
    siteManual_already_registred = ""
    siteManual_succesfully_registred = ""
    siteManual_siteName_label = ""
    siteManual_title = ""
    siteManual_title_label = ""
    siteName_text_empty_title = ""
    siteName_text_empty = ""
    internaldomain_successfully_registred_title = "" 
    internaldomain_successfully_registred = ""
    internaldomain_log = ""
    internaldomainCSV_title = ""
    internaldomainCSV_title_label = "" 
    internaldomain_already_registred_title = ""
    internaldomain_already_registred = ""
    internaldomain_succesfully_registred = ""
    internaldomain_Name_label = ""
    internaldomain_too_long_title = ""
    internaldomain_too_long = ""
    investigate_title = ""
    investigate_check_label = ""
    investigate_typeURL_label = ""
    investigate_clearBtn = ""
    investigate_addBtn = ""
    investigate_checkBtn = ""
    investigate_addblacklistwindow_label = ""
    investigate_message_notCategorized = ""
    investigate_message_status_clean = ""
    investigate_message_status_malicious = ""
    investigate_message_status_notClassified = ""
    investigate_labeldomain = ""
    investigate_labelstatus = ""
    investigate_labelcategorysec = ""
    investigate_labelcategorycontent = ""
    investigate_notallowed = ""
    investigate_invalidtoken = ""
    investigate_domainName_text_empty = ""
    investigate_menu_title = ""
    reporting_menu_title = ""
    reporting_title = ""
    reporting_title_label = ""
    reporting_btn_from = ""
    reporting_btn_to = ""
    reporting_btn_generateReport = ""
    reporting_btn_pickDate = ""
    reporting_success_message = ""
    reporting_empty_result = ""
    invalid_reporting_default = ""
    reporting_empty_FromDate = ""
    reporting_empty_toDate = ""  
    reporting_empy_date_title = ""
    reporting_date_invalid = ""
    reporting_date_invalid_title = ""
############################# Script Version #############################
versao = 'v1.6'


############################# Criando arquivo de configuração na primeira execução do script #############################
#Criar pasta no home do usuario 
folderPath = '~/.umbrella_api_calls'
fullFolderPath = os.path.expanduser(folderPath)
if not os.path.exists(fullFolderPath):
    os.makedirs(fullFolderPath)

#Criar pasta das imagens 
folderImagesPath = '~/.umbrella_api_calls/images'
fullFolderImagesPath = os.path.expanduser(folderImagesPath)
if not os.path.exists(fullFolderImagesPath):
    os.makedirs(fullFolderImagesPath)

#Criar pasta das traduções 
folderTranslationsPath = '~/.umbrella_api_calls/translations'
fullFolderTranslationsPath = os.path.expanduser(folderTranslationsPath)
if not os.path.exists(fullFolderTranslationsPath):
    os.makedirs(fullFolderTranslationsPath)

#Criar pasta dos logs 
folderLogsPath = '~/.umbrella_api_calls/logs'
fullFolderLogsPath = os.path.expanduser(folderLogsPath)
if not os.path.exists(fullFolderLogsPath):
    os.makedirs(fullFolderLogsPath)

#Criar pasta dos reports 
folderReportsPath = '~/.umbrella_api_calls/reports'
fullFolderReportsPath = os.path.expanduser(folderReportsPath)
if not os.path.exists(fullFolderReportsPath):
    os.makedirs(fullFolderReportsPath)



configfile = "~/.umbrella_api_calls/config" 
configFilePath = os.path.expanduser(configfile)
if not os.path.isfile(configFilePath):
    #Cria arquivo de configuração
    f = open(configFilePath, "x")
    f.close()

    #Adiciona valores iniciais no arquivo de configuração
    f = open(configFilePath, "w")
    f.write("[Umbrella]\n")
    f.write("organization_id = <Organization ID>\n")
    f.write("management_api_key = <Umbrella Management API Key>\n")
    f.write("management_secret_key = <Umbrella Management Secret Key>\n")
    f.write("reporting_api_key = <Umbrella Reporting API Key>\n")
    f.write("reporting_secret_key = <Umbrella Reporting Secret Key>\n")
    f.write("InvestigateKey = <Umbrella Investigate API Key>\n")
    f.write("[Language]\n")
    f.write("lang = English")
    f.close()

#URLS de download
icon_download_url = 'https://raw.githubusercontent.com/ValentimMuniz/Cisco-Umbrella-API-Calls/main/images/umbrella_icon.ico'
backgroundImage_download_url = 'https://raw.githubusercontent.com/ValentimMuniz/Cisco-Umbrella-API-Calls/main/images/umbrella.jpg'
InfoImage_download_url = 'https://raw.githubusercontent.com/ValentimMuniz/Cisco-Umbrella-API-Calls/main/images/info-logo.png'

translation_portugues_download_url = 'https://raw.githubusercontent.com/ValentimMuniz/Cisco-Umbrella-API-Calls/main/translations/frases_portugues.json'
translation_english_download_url = 'https://raw.githubusercontent.com/ValentimMuniz/Cisco-Umbrella-API-Calls/main/translations/frases_english.json'

backgroundImageFile = fullFolderImagesPath + "/umbrella.jpg" 
iconImageFile = fullFolderImagesPath + "/umbrella_icon.ico"
InfoImageFile = fullFolderImagesPath + "/info-logo.png"
translationFile_portugues = fullFolderTranslationsPath + "/frases_portugues.json"
translationFile_english = fullFolderTranslationsPath + "/frases_english.json"

if not os.path.isfile(backgroundImageFile):
    backgroundImageFile_download = requests.get(backgroundImage_download_url)
    open(backgroundImageFile, 'wb').write(backgroundImageFile_download.content)

if not os.path.isfile(iconImageFile):
    iconImageFile_download = requests.get(icon_download_url)
    open(iconImageFile, 'wb').write(iconImageFile_download.content)

if not os.path.isfile(InfoImageFile):
    InfoImageFile_download = requests.get(InfoImage_download_url)
    open(InfoImageFile, 'wb').write(InfoImageFile_download.content)

if not os.path.isfile(translationFile_portugues):
    translation_portugues_download = requests.get(translation_portugues_download_url)
    open(translationFile_portugues, 'wb').write(translation_portugues_download.content)

if not os.path.isfile(translationFile_english):
    translation_english_download = requests.get(translation_english_download_url)
    open(translationFile_english, 'wb').write(translation_english_download.content)
    
############################# Fim de criando arquivo de configuração na primeira execução do script #############################


############################# Função para ler configuração #############################
def LerConfiguracao():
    global org_id,mgmt_api_key,mgmt_api_secret,reporting_api_key,reporting_api_secret,language,investigate_api_key
    # Lendo arquivo de configuração
    config = configparser.ConfigParser()
    config.read(configFilePath)
    org_id = config['Umbrella']['organization_id']
    mgmt_api_key = config['Umbrella']['management_api_key']
    mgmt_api_secret = config['Umbrella']['management_secret_key']
    reporting_api_key = config['Umbrella']['reporting_api_key']
    reporting_api_secret = config['Umbrella']['reporting_secret_key']
    investigate_api_key = config['Umbrella']['InvestigateKey']
    language = config['Language']['lang']
LerConfiguracao()
############################# Fim de função para ler configuração #############################


############################# Função de primeira vez rodando script #############################
def FirstTimeScript():
    LerConfiguracao()
    OrgNone = False
    if org_id == "<Organization ID>" and mgmt_api_key == "<Umbrella Management API Key>" and mgmt_api_secret == "<Umbrella Management Secret Key>":
       messagebox.showinfo(globalV.firstTimeScript_message_title, globalV.firstTimeScript_message, parent=root)
    if org_id == "<Organization ID>":
        while OrgNone == False:  
            idOrg_input = simpledialog.askstring(globalV.firstTimeScript_ask_titles, globalV.firstTimeScript_ask_orgID, parent=root)           
            if idOrg_input is not None and idOrg_input != "":
                set_value_in_property_file(configFilePath, 'Umbrella', 'organization_id', idOrg_input)
                LerConfiguracao()
                OrgNone = True
                #emailTxt.focus_set() 
            else: 
                messagebox.showerror(globalV.firstTimeScript_empty_orgID_title, globalV.firstTimeScript_empty_orgID, parent=root)

    MgmtAPI = False        
    if mgmt_api_key == "<Umbrella Management API Key>":
        while MgmtAPI == False:  
            mgmt_api_key_input = simpledialog.askstring(globalV.firstTimeScript_ask_titles, globalV.firstTimeScript_ask_mgm_key, parent=root)
            if mgmt_api_key_input is not None and mgmt_api_key_input != "":
                set_value_in_property_file(configFilePath, 'Umbrella', 'management_api_key', mgmt_api_key_input)
                LerConfiguracao()
                MgmtAPI = True
                #emailTxt.focus_set()
            else: 
                messagebox.showerror(globalV.firstTimeScript_empty_mgmg_key_title, globalV.firstTimeScript_empty_mgmg_key, parent=root)

    MgmtSecretAPI = False
    if mgmt_api_secret == "<Umbrella Management Secret Key>":
        while MgmtSecretAPI == False:  
            mgmt_api_secret_input = simpledialog.askstring(globalV.firstTimeScript_ask_titles, globalV.firstTimeScript_ask_mgm_secret, parent=root)
            if mgmt_api_secret_input is not None and mgmt_api_secret_input != "":
                set_value_in_property_file(configFilePath, 'Umbrella', 'management_secret_key', mgmt_api_secret_input)
                LerConfiguracao()
                MgmtSecretAPI = True
                #emailTxt.focus_set()
            else: 
                messagebox.showerror(globalV.firstTimeScript_empty_secret_key_title, globalV.firstTimeScript_empty_secret_key, parent=root)

    ReportAPI = False        
    if reporting_api_key == "<Umbrella Reporting API Key>":
        while ReportAPI == False:  
            #mudar tradução
            report_api_key_input = simpledialog.askstring(globalV.firstTimeScript_ask_titles, globalV.firstTimeScript_ask_reporting_key, parent=root)
            if report_api_key_input is not None and report_api_key_input != "":
                set_value_in_property_file(configFilePath, 'Umbrella', 'reporting_api_key', report_api_key_input)
                LerConfiguracao()
                ReportAPI = True
                #emailTxt.focus_set()
            else: 
                #mudar
                messagebox.showerror(globalV.firstTimeScript_empty_reporting_key_title, globalV.firstTimeScript_empty_reporting_key, parent=root)
    
    ReportSecret = False        
    if reporting_api_secret == "<Umbrella Reporting Secret Key>":
        while ReportSecret == False:  
            reporting_api_secret_input = simpledialog.askstring(globalV.firstTimeScript_ask_titles, globalV.firstTimeScript_ask_reporting_secret, parent=root)
            if reporting_api_secret_input is not None and reporting_api_secret_input != "":
                set_value_in_property_file(configFilePath, 'Umbrella', 'reporting_secret_key', reporting_api_secret_input)
                LerConfiguracao()
                ReportSecret = True
                #emailTxt.focus_set()
            else: 
                #mudar
                messagebox.showerror(globalV.firstTimeScript_empty_reporting_secret_key_title, globalV.firstTimeScript_empty_reporting_secret_key, parent=root)
    
    InvestigateKey = False        
    if investigate_api_key == "<Umbrella Investigate API Key>":
        while InvestigateKey == False:  
            investigate_api_input = simpledialog.askstring(globalV.firstTimeScript_ask_titles, globalV.firstTimeScript_ask_investigate_key, parent=root)
            if investigate_api_input is not None and investigate_api_input != "":
                set_value_in_property_file(configFilePath, 'Umbrella', 'InvestigateKey', investigate_api_input)
                LerConfiguracao()
                InvestigateKey = True
                #emailTxt.focus_set()
            else: 
                #mudar
                messagebox.showerror(globalV.firstTimeScript_empty_investigate_key_title, globalV.firstTimeScript_empty_investigate_key, parent=root)

############################# Funções para limpeza das varáveis #############################
    

############################# Headers e URL do HTTP REQUESTS #############################
headers = {'Content-Type': 'application/json','Accept': 'application/json'}
header_investigate = { 'Authorization': 'Bearer ' + investigate_api_key}

# management api url, usado para pegar os posts para as funcionalidades do Umbrella
mgmt_url = 'https://management.api.umbrella.com/v1'

# management api url, usado para pegar o access token do reporting api
mgmt_url_token = 'https://management.api.umbrella.com/auth/v2/oauth2/token'

# management api url, used to get access token for reporting api
reporting_url = 'https://reports.api.umbrella.com/v2/'

# investigate api url
investigate_url = 'https://investigate.api.umbrella.com'
############################# Fim de Headers e URL do HTTP REQUESTS #############################


#############################  Função para setar aglum valor no arquivo de config #############################
def set_value_in_property_file(file_path, section, key, value):
    config = configparser.RawConfigParser()
    config.read(file_path)
    config.set(section,key,value)                         
    cfgfile = open(file_path,'w+')
    config.write(cfgfile) 
    cfgfile.close()

#############################  Funções para HTTP REQUESTS #############################

#Função para fazer GET das requisições do Umbrella Investigate
def get_request_investigate(endpoint):
    global code_access_token_getrequests_investigate
    r = requests.get(investigate_url+endpoint, headers=header_investigate)
    code_access_token_getrequests_investigate = r.status_code
    if r.status_code == 401 or r.status_code == 403:
        return code_access_token_getrequests_investigate
    elif r.status_code == 405:
        return code_access_token_getrequests_investigate
    body = json.loads(r.content)
    return body


#Função para fazer GET das requisições do Ubrella Management
def get_request(endpoint):
    global code_access_token_getrequests
    r = requests.get(mgmt_url+endpoint, headers=headers, auth=(mgmt_api_key, mgmt_api_secret))
    code_access_token_getrequests = r.status_code
    if r.status_code == 401 or r.status_code == 403:
        return code_access_token_getrequests
    elif r.status_code == 404:
        return code_access_token_getrequests
    body = json.loads(r.content)
    return body
    

#Função para fazer HTTP POST de Internal Domains
def post_destinations_request(endpoint, desturl):
    global code_access_token_destination_post,tempo

    #Se for através de CSV, adicionar sleep para fazer request de 3 em 3 segundos para não dar o erro HTTP 425
    if globalV.manual == False:
        sleep(3)
    # Build the POST data
    dataDest = [{
        "destination": desturl
    }]
    r = requests.post(mgmt_url+endpoint, headers=headers, auth=(mgmt_api_key, mgmt_api_secret), data=json.dumps(dataDest))   
    code_access_token_destination_post = r.status_code
    
    tempo = r.elapsed.total_seconds()
    if r.status_code == 200:
        return tempo
    if r.status_code == 401 or r.status_code == 403:
        return code_access_token_destination_post
    elif r.status_code == 404:
        return code_access_token_destination_post
    elif r.status_code == 400:
        return code_access_token_destination_post
    elif r.status_code == 409:
        return code_access_token_destination_post
    body = json.loads(r.content)
    return body 

#Função para fazer HTTP POST de Internal Domains
def post_internaldomains_request(endpoint, internaldomain):
    global code_access_token_domains_post,tempo
    if globalV.manual == False:
        sleep(3)

    # Build the POST data
    dataDomains = {
        "domain": internaldomain
    }
    r = requests.post(mgmt_url+endpoint, headers=headers, auth=(mgmt_api_key, mgmt_api_secret), data=json.dumps(dataDomains))   
    code_access_token_domains_post = r.status_code
    tempo = r.elapsed.total_seconds()
    if r.status_code == 200:
        return tempo
    if r.status_code == 401 or r.status_code == 403:
        return code_access_token_domains_post
    elif r.status_code == 404:
        return code_access_token_domains_post
    elif r.status_code == 400:
        return code_access_token_domains_post
    elif r.status_code == 409:
        return code_access_token_domains_post
    body = json.loads(r.content)
    return body

#Função para fazer HTTP POST de Sites
def post_site_request(endpoint, sites):
    global code_access_token_site_post,tempo
    if globalV.manual == False:
        sleep(3)

    #Motando o data do POST
    dataSites = {
        "name": sites
    }
   
    r = requests.post(mgmt_url+endpoint, headers=headers, auth=(mgmt_api_key, mgmt_api_secret), data=json.dumps(dataSites))
    code_access_token_site_post = r.status_code
    tempo = r.elapsed.total_seconds()
    if r.status_code == 200:
        return tempo
    if r.status_code == 401 or r.status_code == 403:
        return code_access_token_site_post
    elif r.status_code == 404:
        return code_access_token_site_post
    elif r.status_code == 409:
        return code_access_token_site_post
    body = json.loads(r.content)
    return body
    
#Função para fazer HTTP POST de Internal Networks
def post_internalnetworks_request(endpoint, internalnetworks):
    global code_access_token_net_post,tempo
    sleep(5)
    r = requests.post(mgmt_url+endpoint, headers=headers, auth=(mgmt_api_key, mgmt_api_secret), data=internalnetworks)   
    code_access_token_net_post = r.status_code
    #print(str(r.status_code) + ", " + str(r.reason))
    tempo = r.elapsed.total_seconds()
    if r.status_code == 200:
        return tempo
    if r.status_code == 401 or r.status_code == 403: 
        return code_access_token_net_post
    elif r.status_code == 404:
        return code_access_token_net_post
    elif r.status_code == 400:
        return code_access_token_net_post
    body = json.loads(r.content)
    return body

#Função para fazer GET das requisições
def getToken():
    global code_access_token_reporting_post
    r = requests.post(mgmt_url_token, headers=headers, auth=(reporting_api_key, reporting_api_secret))
    code_access_token_reporting_post = r.status_code
    if r.status_code == 401 or r.status_code == 403:
        return code_access_token_reporting_post

    body = json.loads(r.content)
    return body['access_token']
    
def reportingGet(endpoint, accesstoken):
    global code_access_token_get_report
    headers['Authorization'] = 'Bearer {}'.format(accesstoken)
    r = requests.get(reporting_url+endpoint, headers=headers)
    code_access_token_get_report = r.status_code
    if r.status_code == 401 or r.status_code == 403:
        return code_access_token_get_report

    body = json.loads(r.content)
    return body

############################# Fim de funções para HTTP REQUESTS #############################


############################# Funções para validações do Internal Networks #############################
#Função para saber se o IP informado no CSV está correto, caso não gerar logs
def checkValidIpNetwork(ip, name):
    try:
        ipaddress.IPv4Network(ip)
        return True
    except ValueError:
        now = datetime.now()
        # dd/mm/YY H:M:S
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
        if not os.path.isfile(fullFolderLogsPath +'/wrongips.log'):
            f = open(fullFolderLogsPath + "/wrongips.log", "x")
            f.close()
        f = open(fullFolderLogsPath + "/wrongips.log", "a")
        f.write("--------------------------------------")
        f.write("\n")
        f.write(str(dt_string))
        f.write("\n")
        f.write(globalV.invalid_ip_log1 + ip + globalV.invalid_ip_log2 + name)
        f.close()
        return False

# Função para remover duplicados exatos no CSV 
def removeduplicate(it):
    seen = set()
    for x in it:
        t = tuple(x.items())
        if t not in seen:
            yield x
            seen.add(t)
############################# Fim de funções de validações do Internal Networks #############################


############################# Funções pra abrir Explorer para escolher CSV #############################
def browseInternalDomains(closing): 
    global internaldomainCSV,fileNameCSV_InternalDomain
    if closing == False:
        filenameInternalDomain = filedialog.askopenfilename(title = globalV.fileDiaglog_explorer, filetypes=(('CSV files', '*.csv'),))
        internaldomainWindow.focus_set()
        internaldomainCSV = filenameInternalDomain
        path = Path(internaldomainCSV)
        fileNameCSV_InternalDomain = path.name
        if internaldomainCSV != "":
            labelSelectedCSVDomain.config(text = globalV.label_csv_selected + path.name)
    else:
        internaldomainCSV = ""

def browseSitesCSV(closing): 
    global SitesCSV, fileNameCSV_Sites
    if closing == False:   
        filenameSites = filedialog.askopenfilename(title = globalV.fileDiaglog_explorer, filetypes=(('CSV files', '*.csv'),))
        SitesCSVWindow.focus_set()
        SitesCSV = filenameSites
        path = Path(SitesCSV)
        fileNameCSV_Sites = path.name
        if SitesCSV != "":
            labelSelectedCSVSite.config(text = globalV.label_csv_selected + path.name)
    else:
        SitesCSV = ""

def browseInternalNet(closing): 
    global internalNetCSV,fileNameCSV_InternalNetwork
    if closing == False:
        filenameInternalNet = filedialog.askopenfilename(title = globalV.fileDiaglog_explorer, filetypes=(('CSV files', '*.csv'),))
        internalnetWindow.focus_set()
        internalNetCSV = filenameInternalNet
        path = Path(internalNetCSV)
        fileNameCSV_InternalNetwork = path.name
        if internalNetCSV != "":
            labelSelectedCSVNet.config(text = globalV.label_csv_selected + path.name)
    else:
        internalNetCSV = ""

def browseDestination(closing): 
    global DestinationCSV,fileNameCSV_Destination
    if closing == False:
        filenameInternalNet = filedialog.askopenfilename(title = globalV.fileDiaglog_explorer, filetypes=(('CSV files', '*.csv'),))
        DestinationListsWindow.focus_set()
        DestinationCSV = filenameInternalNet
        path = Path(DestinationCSV)
        fileNameCSV_Destination = path.name
        if DestinationCSV != "":
            labelSelectedCSVDestination.config(text = globalV.label_csv_selected + path.name)
    else:
        DestinationCSV = ""
############################# Fim de funções pra abrir Explorer para escolher CSV #############################


############################# Funções para limpeza das varáveis #############################
def clearInternalNet():
    global internalNetCSV
    internalNetCSV = ""
    labelSelectedCSVNet.config(text = '')
    cmbSites.current(0)
    progressbar_net.place_forget()

def clearDestination():
    global DestinationCSV
    DestinationCSV = ""
    labelSelectedCSVDestination.config(text = '')
    cmbDestinations.current(0)
    progressbar_destination.place_forget()

def clearInternalDomain():
    global internaldomainCSV
    internaldomainCSV = ""
    labelSelectedCSVDomain.config(text = '')
    progressbar_domain.place_forget()

def clearSite():
    global SitesCSV
    SitesCSV = ""
    labelSelectedCSVSite.config(text = '')
    progressbar_site.place_forget()

def clearReporting(clear):
    if clear == "from":
        labelSelectedFromDate.config(text = '')
    elif clear == "to":
        labelSelectedToDate.config(text = '')
    elif clear == "all":
        labelSelectedFromDate.config(text = '')
        labelSelectedToDate.config(text = '')
    progressbar_reporting.place_forget()

############################# Fim de funções para limpeza das varáveis #############################


############################# Barra de progresso #############################


####QUANDO FOR CHAMAR O thread TIPO, TEM QUE SER SEM OS PARENTESES (), SE NAO VAI CHAMAR A FUNÇÃO E NAO O thread 
def start_progress_thread(event, pg_bar, tipo):
    global progress_bar_tipo
    progress_bar_tipo = pg_bar
    if tipo == "site":
        thread_tipo = CadastrarSitesCSV
        pg_bar.place(relx=.015, rely=.62)
    if tipo == "domain":
        thread_tipo = CadastrarInternalDomains
        pg_bar.place(relx=.015,rely=.6)
    if tipo == "internalnet":
        confirmarSite = messagebox.askquestion(globalV.confirmation_title, globalV.confirmation_site_assign + cmbSites.get() + " ?", icon='warning')
        if confirmarSite == 'no':
            pg_bar.place_forget()
            return messagebox.showwarning(globalV.choose_valid_site_title, globalV.choose_valid_site, parent=internalnetWindow)    
        else:
            thread_tipo = CadastrarInternalNet_SiteID
            pg_bar.place(relx=.012,rely=.87)
    if tipo == "destination":
        confirmarDest = messagebox.askquestion(globalV.confirmation_title, globalV.confirmation_list_assign + cmbDestinations.get(), icon='warning')
        if confirmarDest == 'no':
            pg_bar.place_forget()
            return messagebox.showwarning(globalV.choose_valid_list_title, globalV.choose_valid_list, parent=DestinationListsWindow)  
        else:
            thread_tipo = CadastrarDestinations_SiteID
            pg_bar.place(relx=.012,rely=.87)
    if tipo == "reporting":
        pg_bar.place(relx=.015,rely=.65)
        thread_tipo = getReport
        

    global thread
    thread = threading.Thread(target=thread_tipo)
    thread.daemon = True
    pg_bar.start()
    thread.start()
    root.after(20, check_progress_thread)

def check_progress_thread():
    
    if thread.is_alive():
        root.after(20, check_progress_thread)
    else:
        progress_bar_tipo.stop()

############################# Fim de progresso #############################

############################# Funções pra quando fechar a janela zerar as variáveiis #############################
def on_closingConfig():
    configFileWindow.destroy()

def on_closing_reporting():
    ReportingWindow.destroy()

def on_closingMenu():
    LerConfiguracao()
    root.deiconify()  #voltar a tela de login a aparecer
    MenuPrincipal.destroy() #destruir a tela de menu principal
    emailTxt.delete('1.0', END)
    emailTxt.focus_set()

def on_closingDomain():
    internaldomainWindow.destroy()
    browseInternalDomains(True)
    MenuPrincipal.attributes("-topmost", True)
    MenuPrincipal.lift()
    MenuPrincipal.focus_force()

def on_closingNet():
    internalnetWindow.destroy()
    browseInternalNet(True)
    MenuPrincipal.attributes("-topmost", True)
    MenuPrincipal.lift()
    MenuPrincipal.focus_force()

def on_closingDestination():
    DestinationListsWindow.destroy()
    browseDestination(True)
    MenuPrincipal.attributes("-topmost", True)
    MenuPrincipal.lift()
    MenuPrincipal.focus_force()

def on_closingSitesCSV():
    SitesCSVWindow.destroy()
    browseSitesCSV(True)
    MenuPrincipal.attributes("-topmost", True)
    MenuPrincipal.lift()
    MenuPrincipal.focus_force()
    
############################# Fim de funções para quando fechar a janela zerar as variáveis #############################


############################# Função para formatar a string do wrongCSV para remover alguns caracteres #############################
def formatString(text):
    for ch in ["[", "]" , "'"]:
        text = text.replace(ch, '')
    return text
############################# Fim de função para formatar a string do wrongCSV para remover alguns caracteres #############################


############################# Função para checkar as colunas no CSV #############################
def checkCSVColumns(csvname, tipo):
    if tipo == 'domain':
        fcheck = open(csvname, 'r',encoding='utf-8-sig')
        readercheck = list(reader(fcheck))
        #Checar se o CSV tem 1 coluna
        wrongCSVLine = ""
        wrongCSV = False
        for row in range(len(readercheck)):
            if len(readercheck[row]) != 1:
                linha = str(row+1)
                wrongCSVLine += str(globalV.wrong_csv_line + linha + " -> " + str(readercheck[row]) + "\n")
                wrongCSV = True
            
        if wrongCSV == True:
            wrongCSVLine = formatString(wrongCSVLine)
            labelSelectedCSVDomain.config(text = '')
            now = datetime.now()
            # dd/mm/YY H:M:S
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            if not os.path.isfile(fullFolderLogsPath + '/wrongCSV.log'):
                fLog = open(fullFolderLogsPath + "/wrongCSV.log", "x")
                fLog.close()
            fLog = open(fullFolderLogsPath + "/wrongCSV.log", "a")
            fLog.write("--------------------------------------------------")
            fLog.write("\n") 
            fLog.write(str(dt_string))
            fLog.write("\n")
            fLog.write(globalV.csv_error_InternalDomains_log + csvname)
            fLog.write("\n")
            fLog.write(wrongCSVLine)
            fLog.close()
            return "wrongCSV"
        fcheck.close()
    elif tipo == 'sites':
        fcheck = open(csvname, 'r',encoding='utf-8-sig')
        readercheck = list(reader(fcheck))
        #Checar se o CSV tem 1 coluna
        wrongCSVLine = ""
        wrongCSV = False
        for row in range(len(readercheck)):
            if len(readercheck[row]) != 1:
                linha = str(row+1)
                wrongCSVLine += str(globalV.wrong_csv_line + linha + " -> " + str(readercheck[row]) + "\n")
                wrongCSV = True
            
        if wrongCSV == True:
            wrongCSVLine = formatString(wrongCSVLine)
            labelSelectedCSVSite.config(text = '')
            now = datetime.now()
            # dd/mm/YY H:M:S
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            if not os.path.isfile(fullFolderLogsPath + '/wrongCSV.log'):
                fLog = open(fullFolderLogsPath + "/wrongCSV.log", "x")
                fLog.close()
            fLog = open(fullFolderLogsPath + "/wrongCSV.log", "a")
            fLog.write("--------------------------------------------------")
            fLog.write("\n") 
            fLog.write(str(dt_string))
            fLog.write("\n")
            fLog.write(globalV.csv_error_Sites_log + csvname)
            fLog.write("\n")
            fLog.write(wrongCSVLine)
            fLog.close()
            return "wrongCSV"
        fcheck.close()
    elif tipo == 'destination':
        fcheck = open(csvname, 'r',encoding='utf-8-sig')
        readercheck = list(reader(fcheck))
        #Checar se o CSV tem 1 coluna
        wrongCSVLine = ""
        wrongCSV = False
        for row in range(len(readercheck)):
            if len(readercheck[row]) != 1:
                linha = str(row+1)
                wrongCSVLine += str(globalV.wrong_csv_line + linha + " -> " + str(readercheck[row]) + "\n")
                wrongCSV = True
            
        if wrongCSV == True:
            wrongCSVLine = formatString(wrongCSVLine)
            labelSelectedCSVDestination.config(text = '')
            now = datetime.now()
            # dd/mm/YY H:M:S
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            if not os.path.isfile(fullFolderLogsPath + '/wrongCSV.log'):
                fLog = open(fullFolderLogsPath + "/wrongCSV.log", "x")
                fLog.close()
            fLog = open(fullFolderLogsPath + "/wrongCSV.log", "a")
            fLog.write("--------------------------------------------------")
            fLog.write("\n") 
            fLog.write(str(dt_string))
            fLog.write("\n")
            fLog.write(globalV.csv_error_Destinations_log + csvname)
            fLog.write("\n")
            fLog.write(wrongCSVLine)
            fLog.close()
            return "wrongCSV"
        fcheck.close()
    elif tipo == 'internalnet':
        fcheck = open(csvname, 'r', encoding='utf-8-sig')
        readercheck = list(reader(fcheck))
        #Checar se o CSV tem 3 colunas
        wrongCSVLine = ""
        wrongCSV = False
        for row in range(len(readercheck)):
            if len(readercheck[row]) != 3:
                linha = str(row+1)
                wrongCSVLine += str(globalV.wrong_csv_line + linha + " -> " + str(readercheck[row]) + "\n")
                wrongCSV = True
        
        if wrongCSV == True:
            wrongCSVLine = formatString(wrongCSVLine)
            labelSelectedCSVNet.config(text = '')
            now = datetime.now()
            # dd/mm/YY H:M:S
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            if not os.path.isfile(fullFolderLogsPath + '/wrongCSV.log'):
                fLog = open(fullFolderLogsPath + "/wrongCSV.log", "x")
                fLog.close()
            fLog = open(fullFolderLogsPath + "/wrongCSV.log", "a")
            fLog.write("--------------------------------------------------")
            fLog.write("\n") 
            fLog.write(str(dt_string))
            fLog.write("\n")
            fLog.write(globalV.csv_error_InternalNetworks_log + csvname)
            fLog.write("\n")
            fLog.write(wrongCSVLine)
            fLog.close()
            return "wrongCSV"
        fcheck.close()
############################# Fim da função para checkar as colunas no CSV #############################

############################# Função para gerar o report #############################
def getReport():
    if labelSelectedToDate.cget("text") == "" or labelSelectedToDate.cget("text") is None:
        clearReporting("to")
        return messagebox.showerror(globalV.reporting_empy_date_title, globalV.reporting_empty_toDate, parent=ReportingWindow) 
    if labelSelectedFromDate.cget("text") == "" or labelSelectedFromDate.cget("text") is None:
        clearReporting("from")
        return messagebox.showerror(globalV.reporting_empy_date_title, globalV.reporting_empty_FromDate, parent=ReportingWindow) 

    if fromDate > toDate:
        clearReporting("all")
        return messagebox.showerror(globalV.reporting_date_invalid_title, globalV.reporting_date_invalid, parent=ReportingWindow)
    #Gerar o token de reporting
    token = getToken()

    if code_access_token_reporting_post == 200:
        d1 = datetime.strptime(str(fromDate), '%Y-%m-%d')
        d2 = datetime.strptime(str(toDate), '%Y-%m-%d')

        def get_delta(d1, d2):
            delta = d2 - d1
            return delta
        delta = get_delta(d1,d2) 

        #colocar timezone
        recife = tz.gettz('America/Recife')
        cont = 0
        #print("d1 " + str(d1))
        #print("d2 " + str(d2))
        #variáveis para fazer o append cada vez que entrar no for de reporting
        tipo = []
        application = []
        datastamp = [] 
        datatempo = []
        indentities_type = []
        indentities = []
        internalip = []
        externalip = []
        verdict = []
        domain = []
        querytype = []
        categories = []
        blockedapplications = []
        policycategories = []

        #For para pegar todas as horas entre as datas que foram inseridas
        for i in range(delta.days * 24 + 24 +1):
            
            #print("tempo 1 " + str(d1 + td(hours=i)))
            #print("tempo 2 " + str(d1 + td(hours=i+1)))
            tempo1 = d1 + td(hours=i)
            tempo2 = d1 + td(hours=i +1) 
            
            timestamp1 = tempo1.replace(tzinfo=recife).timestamp() * 1000
            timestamp2 = tempo2.replace(tzinfo=recife).timestamp() * 1000
            
            #print("from : " + str(timestamp1))
            #print("to: " + str(timestamp2))
            
            
            string = "/organizations/{}/activity?from={}&to={}&limit=5000".format(org_id,int(timestamp1),int(timestamp2))
            r = reportingGet(string, token)
            if code_access_token_get_report == 200:
                
                if len(r['data']) > 0:
                
                    #For para pegar os valores dentro do GET
                    for valor in r['data']:
                        tipo.append(str(valor['type']))
                        internalip.append(str(valor['internalip']))
                        externalip.append(str(valor['externalip']))
                        verdict.append(str(valor['verdict']))
                        domain.append(str(valor['domain']))
                        querytype.append(str(valor['querytype']))
                        
                        datatempo.append(str(valor['date'] + " " + str(valor['time'])))
                        #Pegar o timestamp e transformar pra data(UTC)
                        dt = datetime.fromtimestamp(int(valor['timestamp']) / 1000.0, tz=timezone.utc)
                        dt = dt.strftime('%Y-%m-%d %H:%M:%S')
                        datastamp.append(str(dt))

                        
                        indentities_type.append(valor['identities'][0]['type']['label'])
                        indentities.append(valor['identities'][0]['label'])
                        
                        #esses ifs é que nesses dados pode vir vazio, e tem que tratar
                        if len(valor['categories']) > 0:
                            categories.append(valor['categories'][0]['label'])
                        else:
                            categories.append("") 
                        if len(valor['policycategories']) > 0:
                            policycategories.append(valor['policycategories'][0]['label'])
                        else:
                            policycategories.append("")
                        
                        if len(valor['blockedapplications']) > 0:
                            blockedapplications.append(valor['blockedapplications'][0]['label'])
                        else:
                            blockedapplications.append("")

                        if len(valor['allapplications']) > 0:
                            application.append(valor['allapplications'][0]['label'])
                        else:
                            application.append("")
                        
                        #print("Working...")
                        cont = cont + 1

                if cont > 0 :
                    a = {'Type':tipo,'DateTime':datastamp,'Identities':indentities,'Identity Types':indentities_type, 'Internal IP Address':internalip,'External IP Address':externalip,
                    'Action':verdict,'Domain':domain,'Query Type':querytype,'Categories':categories, 'Blocked Categories':blockedapplications, 'Policy Categories': policycategories,
                    'Application':application}

                    df = pd.DataFrame.from_dict(a, orient='index')
                    df = df.transpose()
                    now = datetime.now()

                    datetimeNameFile = now.strftime("%d/%m/%Y").replace("/", "")
                    
                    #df.to_csv('umbrella_valentim.csv', header=True, index=False)
                    df.to_csv(fullFolderReportsPath+'/umbrella-report-{}-{}.csv'.format(datetimeNameFile,random.randint(2999,4999)), header=True, index=False)
                    clearReporting("all")
                    return messagebox.showinfo(globalV.success_title, globalV.reporting_success_message + str(cont), parent=ReportingWindow)
                else:
                    clearReporting("all")
                    return messagebox.showinfo(globalV.reporting_empty_result, globalV.reporting_empty_result, parent=ReportingWindow)
            else:
                if code_access_token_get_report == 401 or code_access_token_get_report == 403:
                    clearReporting("all")
                    return messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_reporting_default, parent=ReportingWindow) 
    else:
        if code_access_token_reporting_post == 401 or code_access_token_reporting_post == 403:
            clearReporting("all")
            return messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_reporting_default, parent=ReportingWindow) 

#Pegar informações da data escolhida para 'From'
def getCalFrom():
        global fromDate
        fromDate = calFrom.selection_get()
        labelSelectedFromDate.config(text = globalV.reporting_btn_from+": {}".format(fromDate))
        CalendarFromWindow.destroy()

#Pegar informações da data escolhida para 'To'
def getCalTo():
        global toDate
        toDate = calTo.selection_get()
        labelSelectedToDate.config(text = globalV.reporting_btn_to+": {}".format(toDate))
        CalendaToWindow.destroy()

todays_date = date.today()
#Janela de calendario From
def CalendarFrom(): 
    global calFrom,CalendarFromWindow
    CalendarFromWindow = Toplevel(root)
    CalendarFromWindow.minsize(500,280)
    CalendarFromWindow.resizable(0,0)
    #CalendarFromWindow.wm_iconbitmap(iconImageFile)
    center(CalendarFromWindow)
    calFrom = Calendar(CalendarFromWindow,
                   font="Calibri 14", selectmode='day',
                   cursor="hand1", year=todays_date.year, month=todays_date.month, day=todays_date.day)
    calFrom.pack(fill='both', expand=False)
    ttk.Button(CalendarFromWindow, text=globalV.reporting_btn_pickDate, command=getCalFrom).pack()

#Janela de calendario To
def CalendarTo(): 
    global calTo,CalendaToWindow
    CalendaToWindow = Toplevel(root)
    CalendaToWindow.minsize(500,280)
    CalendaToWindow.resizable(0,0)
    #CalendarFromWindow.wm_iconbitmap(iconImageFile)
    center(CalendaToWindow)
    calTo = Calendar(CalendaToWindow,
                   font="Arial 14", selectmode='day',
                   cursor="hand1", year=todays_date.year, month=todays_date.month, day=todays_date.day)
    calTo.pack(fill='both', expand=False)
    ttk.Button(CalendaToWindow, text=globalV.reporting_btn_pickDate, command=getCalTo).pack()


############################# Função para bindar quando pressionar a tecla Enter #############################
def enterPressedReport(e):
    if e.keycode == 13:
        start_progress_thread(None,progressbar_destination,"reporting")
############################# Janela Reporting ############################# 
def openMenuReporting():   
    # Variavel global poist tem uso em outras funções
    global ReportingWindow,labelSelectedFromDate,labelSelectedToDate,progressbar_reporting
    
    # Criar a Janela via Toplevel e setar parametros iniciais 
    ReportingWindow = Toplevel(root) 
    ReportingWindow.title(globalV.reporting_title) 
    ReportingWindow.wm_iconbitmap(iconImageFile)
    ReportingWindow.minsize(600,300)
    center(ReportingWindow)
    ReportingWindow.resizable(0,0)   
    ReportingWindow.configure(background = '#F0FFFF')

    labelTitle = Label(ReportingWindow,text=globalV.reporting_title_label,font='Calibri 15 bold', bg='#F0FFFF')
    labelTitle.place(relx=.015,rely=.0)

    botao_from = HoverButton(ReportingWindow,text=globalV.reporting_btn_from,  width=10, activebackground='#0688fa', bg='#2dabf9', command = CalendarFrom)
    botao_from.place(relx=.015, rely=.17)

    labelSelectedFromDate = Label(ReportingWindow,text='',font='Calibri 12 bold', fg ='#0ea3da', bg='#F0FFFF')
    labelSelectedFromDate.place(relx=.15,rely=.17)

    botao_to = HoverButton(ReportingWindow,text=globalV.reporting_btn_to,  width=10, activebackground='#0688fa', bg='#2dabf9', command = CalendarTo)
    botao_to.place(relx=.015, rely=.28)

    labelSelectedToDate = Label(ReportingWindow,text='',font='Calibri 12 bold', fg ='#0ea3da', bg='#F0FFFF')
    labelSelectedToDate.place(relx=.15,rely=.28)

    progressbar_reporting = ttk.Progressbar(ReportingWindow, style="bar.Horizontal.TProgressbar", orient="horizontal", length=150, mode="indeterminate")
    
    botao_gerar = HoverButton(ReportingWindow,text = globalV.reporting_btn_generateReport,  width=20, activebackground='#0688fa', bg='#2dabf9', command = lambda:start_progress_thread(None, progressbar_reporting, "reporting"))
    botao_gerar.place(relx=.015, rely=.45)
  
    
    ReportingWindow.bind('<KeyPress>', enterPressedReport)
    ReportingWindow.protocol("WM_DELETE_WINDOW", on_closing_reporting)


############################# Função para bindar quando pressionar a tecla Enter #############################
def enterPressedDestinationManual(e):
    if e.keycode == 13:
        destinationIDselected = str(listaIdDestinationsManual[cmbDestinationsManual.current()]).rstrip()
        destination = destinationTxt.get("1.0","end-1c").strip().rstrip()
        CadastrarDestinationManual(destination, destinationIDselected)

#Funcão para pegar o ID da lista de Destination selecionado e chamar a função de cadastro!
def CadastrarDestinationManual_ID():
    destinationIDselected = str(listaIdDestinationsManual[cmbDestinationsManual.current()]).rstrip()
    destination = destinationTxt.get("1.0","end-1c").strip().rstrip()
    CadastrarDestinationManual(destination, destinationIDselected)

############################# Janela para Destination Manual #############################
def openMenuDestinationManual():  
    global DestinationManual,cmbDestinationsManual,listaIdDestinationsManual,destinationTxt
    # Criar a Janela via Toplevel e setar parametros iniciais
    DestinationManual = Toplevel(root) 
    DestinationManual.title(globalV.destinationManual_title) 
    DestinationManual.wm_iconbitmap(iconImageFile)
    DestinationManual.minsize(400,50)
    center(DestinationManual)
    DestinationManual.resizable(0,0)
    DestinationManual.configure(background='#F0FFFF')

    r_get_destinations = get_request('/organizations/{}/destinationlists'.format(org_id))

    #Fazer o get para pritar a lista de destinationslists e só proceder se estiver OK
    if code_access_token_getrequests == 200:
        #combobox dos Sites
        cmbDestinationsManual = ttk.Combobox(DestinationManual,state="readonly", width = 20)

        #Adicionar os names dos Sites ao combobox, e em seguida ja pegar seu id e jogar na lista de id_sites
        listaIdDestinationsManual = []
        for sites in r_get_destinations['data']:
            cmbDestinationsManual['value'] = (*cmbDestinationsManual['values'], sites['name'])
            listaIdDestinationsManual.append(sites['id'])

        label = Label(DestinationManual,text=globalV.destinationManual_title_label, font='Calibri 14 bold', bg='#F0FFFF')
        label.place(relx=.015, rely=.0)
    
        label = Label(DestinationManual,text=globalV.destinationManual_destination_text, font='Calibri 10 bold', bg='#F0FFFF')
        label.place(relx=.015, rely=.2)

        destinationTxt = Text(DestinationManual, width=21, height=1)
        destinationTxt.place(relx=.21, rely=.2)
        destinationTxt.focus_set() 

        labeldest = Label(DestinationManual,text=globalV.destination_list_assign_label, font='Calibri 10 bold', bg='#F0FFFF')
        labeldest.place(relx=.015, rely=.4)

        cmbDestinationsManual.place(relx=.35, rely=.4)
        cmbDestinationsManual.current(0) 
        #bindar para remover toda vez que fica selecionado, faz com que a janela fique com o foco
        cmbDestinationsManual.bind("<<ComboboxSelected>>",lambda e: DestinationManual.focus())

        cadastrarBtn = HoverButton(DestinationManual,text=globalV.send_btn,  width=23, activebackground='#0688fa', bg='#2dabf9', command = CadastrarDestinationManual_ID)
        cadastrarBtn.place(relx=.015, rely=.6)

        DestinationManual.bind('<KeyPress>', enterPressedDestinationManual)

    elif code_access_token_getrequests == 401 or code_access_token_getrequests == 403:
        messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_mgmt_default, parent=DestinationManual)
    elif code_access_token_getrequests == 404:
        messagebox.showerror(globalV.invalid_orgID_title, globalV.invalid_orgID_default, parent=DestinationManual)

############################# Função para cadastrar novo destino manualmente #############################
def CadastrarDestinationManual(destination,destinationId):
    # variavel pra checkar se um destino ja esta cadastrado
    cadastrado = False
    if not destination:
        destinationTxt.focus_set()
        return messagebox.showinfo(globalV.destinationName_text_empty_title, globalV.destinationName_text_empty, parent=DestinationManual)
    
    r_get_destinations = get_request('/organizations/{}/destinationlists/{}/destinations'.format(org_id,destinationId))
    #Só procede o GET se for Status ok (200), se não informar o que esta errado
    if code_access_token_getrequests == 200:
        for ja_cadastrado in r_get_destinations['data']:
                if ja_cadastrado['destination'] == destination:
                    cadastrado = True
                    break
        if cadastrado == False:
            globalV.manual = globalV.manual = True
            post_destinations_request('/organizations/{}/destinationlists/{}/destinations'.format(org_id,destinationId), destination)

            if code_access_token_destination_post == 200:
                destinationTxt.delete('1.0', END)
                destinationTxt.focus_set()
                return messagebox.showinfo(globalV.success_title, globalV.destinationManual_destination_text + destination + globalV.destinationManual_successfully_regitred + cmbDestinationsManual.get(), parent=DestinationManual)
            elif code_access_token_destination_post == 401 or code_access_token_destination_post == 403:
                return messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_mgmt_default, parent=DestinationManual)
            elif code_access_token_destination_post == 404:
                return messagebox.showerror(globalV.invalid_orgID_title, globalV.invalid_orgID_default, parent=DestinationManual)
        else:
            destinationTxt.delete('1.0', END)
            destinationTxt.focus_set()
            return messagebox.showerror(globalV.destinationManual_already_registred_title, destination + globalV.destinationManual_already_registred + cmbDestinationsManual.get(), parent=DestinationManual)
    elif code_access_token_getrequests == 401 or code_access_token_getrequests == 403:
        return messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_mgmt_default, parent=DestinationListsWindow)
    elif code_access_token_getrequests == 404:
        return messagebox.showerror(globalV.invalid_orgID_title, globalV.invalid_orgID_default, parent=DestinationManual)


############################# Função para bindar quando pressionar a tecla Enter #############################
def enterPressedInvestigateSearch(e):
    domainsearch = domainSearchTxt.get("1.0","end-1c").rstrip().strip() 
    if e.keycode == 13:
        if not domainsearch:
            return messagebox.showinfo(globalV.domainName_text_empty_title, globalV.investigate_domainName_text_empty, parent=InvestigateWindow)
        else:
            InvestigateSearch(domainsearch)

############################# Janela de Investigate #############################
def openInvestigate():   
    global InvestigateWindow,domainSearchTxt,labeldomain,labelstatus,labelcategorysec,labelcategorycontent,addBtn
    # Criar a Janela via Toplevel e setar parametros iniciais
    InvestigateWindow = Toplevel(root) 
    InvestigateWindow.title(globalV.investigate_title) 
    InvestigateWindow.wm_iconbitmap(iconImageFile)
    InvestigateWindow.minsize(500,150)
    center(InvestigateWindow)
    InvestigateWindow.resizable(0,0)
    InvestigateWindow.configure(background = '#F0FFFF')
    label = Label(InvestigateWindow,text=globalV.investigate_check_label,font='Calibri 14 bold', bg='#F0FFFF')
    label.place(relx=.015, rely=.0)

    label = Label(InvestigateWindow,text=globalV.investigate_typeURL_label, font='Calibri 10 bold', bg='#F0FFFF')
    label.place(relx=.015, rely=.2)

    domainSearchTxt = Text(InvestigateWindow, width=30, height=1)
    domainSearchTxt.place(relx=.29, rely=.2)
    domainSearchTxt.focus_set()

    labeldomain = Label(InvestigateWindow,text="", font='Calibri 10 bold', bg='#F0FFFF')
    labeldomain.place(relx=.015, rely=.29)

    labelstatus = Label(InvestigateWindow,text="", font='Calibri 10 bold', bg='#F0FFFF')
    labelstatus.place(relx=.015, rely=.38)

    labelcategorycontent = Label(InvestigateWindow,text="", font='Calibri 10 bold', bg='#F0FFFF')
    labelcategorycontent.place(relx=.015, rely=.47)

    labelcategorysec = Label(InvestigateWindow,text="", font='Calibri 10 bold', bg='#F0FFFF')
    labelcategorysec.place(relx=.015, rely=.56)

    checkBtn = HoverButton(InvestigateWindow,text=globalV.investigate_checkBtn,  width=16, activebackground='#0688fa', bg='#2dabf9', command = lambda: InvestigateSearch(domainSearchTxt.get("1.0","end-1c")))
    checkBtn.place(relx=.015, rely=.8)

    addBtn = HoverButton(InvestigateWindow,text=globalV.investigate_addBtn, state="disabled", width=16, activebackground='#0688fa', bg='#2dabf9', command = InvestigateAddToBlackListWindow)
    addBtn.place(relx=.3, rely=.8)

    clearBtn = HoverButton(InvestigateWindow,text=globalV.investigate_clearBtn,  width=16, activebackground='#0688fa', bg='#2dabf9', command = ClearInvestigate)
    clearBtn.place(relx=.585, rely=.8)
    domainSearchTxt.focus_set()
    InvestigateWindow.bind('<KeyPress>', enterPressedInvestigateSearch)

############################# Função para limpar a busca do Investigate #############################
def ClearInvestigate():
    labeldomain.config(text = "")
    labelstatus.config(text = "")
    labelcategorysec.config(text = "")
    labelcategorycontent.config(text = "")
    domainSearchTxt.delete('1.0', END)
    addBtn['state'] = "disabled"
    InvestigateWindow.focus()
    domainSearchTxt.focus_set()
    

############################# Função para adicionar à blackList #############################
def InvestigateSearch(domainName):
    global dominioInvestigate
    dominioInvestigate = domainName.rstrip().strip()
    if not dominioInvestigate:
        domainSearchTxt.focus_set()
        return messagebox.showinfo(globalV.domainName_text_empty_title, globalV.investigate_domainName_text_empty, parent=InvestigateWindow)    

    r_investigate_search = get_request_investigate('/domains/categorization/{}?showLabels'.format(dominioInvestigate))

    #Limpar o txt pra procurar pq se aperta enter o texto continua e depois 'buga'

    domainSearchTxt.delete('1.0', END)
    if code_access_token_getrequests_investigate == 200:
        for keyj, value in r_investigate_search.items():
            status = value['status']
            sec_categories = value['security_categories']
            content_categories = value['content_categories']

        #Jogar as categorias de conteudo em uma variavel para separar por virgula
        result_categories_content = ""
        for i in content_categories:
            result_categories_content += i + ", "

         #Jogar as categorias de segurança em uma variavel para separar por virgula
        result_categories_sec = ""
        for i in sec_categories:
            result_categories_sec += i + ", "

        if not result_categories_content:
            result_categories_content = globalV.investigate_message_notCategorized

        if not result_categories_sec:
            result_categories_sec = globalV.investigate_message_notCategorized

        if status == 1:
            result_status = globalV.investigate_message_status_clean
        elif status == -1:
            result_status = globalV.investigate_message_status_malicious
        elif status == 0:
            result_status = globalV.investigate_message_status_notClassified
          
        labeldomain.config(text = globalV.investigate_labeldomain + dominioInvestigate)
        labelstatus.config(text = globalV.investigate_labelstatus + result_status)
        
        #Se nao for categorizado, adicionar mensagem de nao categorizado
        if result_categories_content == globalV.investigate_message_notCategorized:
            labelcategorycontent.config(text = globalV.investigate_labelcategorycontent + result_categories_content)
        else:
            labelcategorycontent.config(text = globalV.investigate_labelcategorycontent + result_categories_content[:-2])
        
        #Se nao for categorizado, adicionar mensagem de nao categorizado
        if result_categories_sec == globalV.investigate_message_notCategorized:
            labelcategorysec.config(text = globalV.investigate_labelcategorysec + result_categories_sec)
        else:
            labelcategorysec.config(text = globalV.investigate_labelcategorysec + result_categories_sec[:-2])

        #Se for malicioso ou não classificado ativar o botão
        if result_status == globalV.investigate_message_status_malicious or result_status == globalV.investigate_message_status_notClassified:
            addBtn['state'] = "active"

    elif code_access_token_getrequests_investigate == 401 or code_access_token_getrequests_investigate == 403:
        return messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.investigate_invalidtoken, parent=InvestigateWindow)
    elif code_access_token_getrequests_investigate == 401 or code_access_token_getrequests_investigate == 403:
        return messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.investigate_notallowed, parent=InvestigateWindow)


############################# Função para bindar quando pressionar a tecla Enter #############################
def enterPressedInvestigateBlackList(e):
    if e.keycode == 13:
        destinationIDselected = str(destinationsIds[cmbInvestigate_destinations.current()]).rstrip()
        destination = dominioInvestigate
        CadastrarDestinationInvestigate(destination, destinationIDselected)
        
#Funcão para pegar o ID da lista de Destination vindo do Umbrella Invetigate
def GetDestinationListID():
    destinationIDselected = str(destinationsIds[cmbInvestigate_destinations.current()]).rstrip()
    destination = dominioInvestigate
    CadastrarDestinationInvestigate(destination, destinationIDselected)

############################# Função para destino vindo do Umbrella Invetigate #############################
def CadastrarDestinationInvestigate(destination,destinationId):
    # variavel pra checkar se um destino ja esta cadastrado
    cadastrado = False
    
    r_get_destinations = get_request('/organizations/{}/destinationlists/{}/destinations'.format(org_id,destinationId))
    #Só procede o GET se for Status ok (200), se não informar o que esta errado
    if code_access_token_getrequests == 200:
        for ja_cadastrado in r_get_destinations['data']:
                if ja_cadastrado['destination'] == destination:
                    cadastrado = True
                    break
        if cadastrado == False:
            globalV.manual = globalV.manual = True
            post_destinations_request('/organizations/{}/destinationlists/{}/destinations'.format(org_id,destinationId), destination)

            if code_access_token_destination_post == 200:
                #AQUI FECHAR A JANELA              
                ClearInvestigate() 
                InvestigateBlackList.withdraw()
                return messagebox.showinfo(globalV.success_title, globalV.destinationManual_destination_text + destination + globalV.destinationManual_successfully_regitred + cmbInvestigate_destinations.get(), parent=InvestigateBlackList)
            elif code_access_token_destination_post == 401 or code_access_token_destination_post == 403:
                return messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_mgmt_default, parent=InvestigateBlackList)
            elif code_access_token_destination_post == 404:
                return messagebox.showerror(globalV.invalid_orgID_title, globalV.invalid_orgID_default, parent=InvestigateBlackList)
        else:
            #FECHAR A JANELA E DAR CLEAR NA JANELA DO UMBRELLA INVESTIGATE
            ClearInvestigate()
            InvestigateBlackList.withdraw()
            return messagebox.showerror(globalV.destinationManual_already_registred_title, destination + globalV.destinationManual_already_registred + cmbInvestigate_destinations.get(), parent=InvestigateBlackList)
    elif code_access_token_getrequests == 401 or code_access_token_getrequests == 403:
        return messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_mgmt_default, parent=InvestigateBlackList)
    elif code_access_token_getrequests == 404:
        return messagebox.showerror(globalV.invalid_orgID_title, globalV.invalid_orgID_default, parent=InvestigateBlackList)
    
############################# Janela para adicionar à blackList através do Investigate #############################
def InvestigateAddToBlackListWindow():  
    global InvestigateBlackList,cmbInvestigate_destinations,destinationsIds
    # Criar a Janela via Toplevel e setar parametros iniciais
    InvestigateBlackList = Toplevel(root) 
    InvestigateBlackList.title(globalV.investigate_title) 
    InvestigateBlackList.wm_iconbitmap(iconImageFile)
    InvestigateBlackList.minsize(400,50)
    center(InvestigateBlackList)
    InvestigateBlackList.resizable(0,0)
    InvestigateBlackList.configure(background='#F0FFFF')

    r_get_destinations = get_request('/organizations/{}/destinationlists'.format(org_id))

    #Fazer o get para pritar a lista de destinationslists e só proceder se estiver OK
    if code_access_token_getrequests == 200:
        #combobox dos Sites
        cmbInvestigate_destinations = ttk.Combobox(InvestigateBlackList,state="readonly", width = 20)

        #Adicionar os names dos Sites ao combobox, e em seguida ja pegar seu id e jogar na lista de id_sites
        destinationsIds = []
        for sites in r_get_destinations['data']:
            cmbInvestigate_destinations['value'] = (*cmbInvestigate_destinations['values'], sites['name'])
            destinationsIds.append(sites['id'])

        label = Label(InvestigateBlackList,text=globalV.investigate_addblacklistwindow_label, font='Calibri 14 bold', bg='#F0FFFF')
        label.place(relx=.015, rely=.0)
    
        label = Label(InvestigateBlackList,text=labeldomain['text'], font='Calibri 10 bold', bg='#F0FFFF')
        label.place(relx=.015, rely=.2)

        labeldest = Label(InvestigateBlackList,text=globalV.destination_list_assign_label, font='Calibri 10 bold', bg='#F0FFFF')
        labeldest.place(relx=.015, rely=.4)

        cmbInvestigate_destinations.place(relx=.35, rely=.4)
        cmbInvestigate_destinations.current(0) 

        #bindar para remover toda vez que fica selecionado, faz com que a janela fique com o foco
        cmbInvestigate_destinations.bind("<<ComboboxSelected>>",lambda e: InvestigateBlackList.focus())

        cadastrarBtn = HoverButton(InvestigateBlackList,text=globalV.send_btn,  width=23, activebackground='#0688fa', bg='#2dabf9', command = GetDestinationListID)
        cadastrarBtn.place(relx=.015, rely=.6)

        InvestigateBlackList.bind('<KeyPress>', enterPressedInvestigateBlackList)

    elif code_access_token_getrequests == 401 or code_access_token_getrequests == 403:
        messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_mgmt_default, parent=DestinationManual)
    elif code_access_token_getrequests == 404:
        messagebox.showerror(globalV.invalid_orgID_title, globalV.invalid_orgID_default, parent=DestinationManual)



############################# Função para bindar quando pressionar a tecla Enter #############################
def enterPressedDomainManual(e):
    if e.keycode == 13:
        CadastrarNovoInternalDomain(domainTxt.get("1.0","end-1c"))

############################# Janela de Internal Domains Manual #############################
def openMenuDomainManual():   
    global DomainManual,domainTxt
    # Criar a Janela via Toplevel e setar parametros iniciais
    DomainManual = Toplevel(root) 
    DomainManual.title(globalV.internaldomain_title) 
    DomainManual.wm_iconbitmap(iconImageFile)
    DomainManual.minsize(400,50)
    center(DomainManual)
    DomainManual.resizable(0,0)
    DomainManual.configure(background = '#F0FFFF')
    label = Label(DomainManual,text=globalV.internaldomain_title_label,font='Calibri 14 bold', bg='#F0FFFF')
    label.place(relx=.015, rely=.0)
 
    label = Label(DomainManual,text=globalV.internaldomain_Name_label, font='Calibri 10 bold', bg='#F0FFFF')
    label.place(relx=.015, rely=.2)

    domainTxt = Text(DomainManual, width=21, height=1)
    domainTxt.place(relx=.39, rely=.2)
    domainTxt.focus_set()

    cadastrarBtn = HoverButton(DomainManual,text=globalV.send_btn,  width=23, activebackground='#0688fa', bg='#2dabf9', command = lambda: CadastrarNovoInternalDomain(domainTxt.get("1.0","end-1c")))
    #cadastrarBtn = Button(DomainManual, text = "Cadastrar Internal Domain", width=23, command = lambda: CadastrarNovoInternalDomain(domainTxt.get("1.0","end-1c")))
    cadastrarBtn.place(relx=.015, rely=.4)

    DomainManual.bind('<KeyPress>', enterPressedDomainManual)

############################# Função para cadastrar novo Internal Domain manualmente #############################
def CadastrarNovoInternalDomain(domainName):
    domainParsed = domainName.rstrip().strip()
    if not domainParsed:
        domainTxt.focus_set()
        return messagebox.showinfo(globalV.domainName_text_empty_title, globalV.domainName_text_empty, parent=DomainManual)
         
    globalV.manual = True
    post_internaldomains_request('/organizations/{}/internaldomains'.format(org_id), domainParsed)
    if code_access_token_domains_post == 200:
        domainTxt.delete('1.0', END)
        domainTxt.focus_set()
        return messagebox.showinfo(globalV.success_title, globalV.internaldomain_succesfully_registred + domainParsed, parent=DomainManual)
    elif code_access_token_domains_post == 401 or code_access_token_domains_post == 403:
        return messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_mgmt_default, parent=DomainManual)
    elif code_access_token_domains_post == 404:
        return messagebox.showerror(globalV.invalid_orgID_title, globalV.invalid_orgID_default, parent=DomainManual)
    elif code_access_token_domains_post == 400:
        domainTxt.delete('1.0', END)
        domainTxt.focus_set()
        return messagebox.showerror(globalV.internaldomain_too_long_title, globalV.internaldomain_too_long, parent=DomainManual)
    elif code_access_token_domains_post == 409:
        domainTxt.delete('1.0', END)
        domainTxt.focus_set()
        return messagebox.showerror(globalV.internaldomain_already_registred_title, globalV.internaldomain_already_registred + domainParsed, parent=DomainManual)


############################# Função para bindar quando pressionar a tecla Enter #############################
def enterPressedSiteManual(e):
    if e.keycode == 13:
        CadastrarNovoSite(siteTxt.get("1.0","end-1c"))

############################# Janela Sites Manual #############################
def openMenuSiteManual():   
    global SiteManual,siteTxt
    # Criar a Janela via Toplevel e setar parametros iniciais
    SiteManual = Toplevel(root) 
    SiteManual.title(globalV.siteManual_title) 
    SiteManual.wm_iconbitmap(iconImageFile)
    SiteManual.minsize(400,50)
    center(SiteManual)
    SiteManual.resizable(0,0)
    SiteManual.configure(background='#F0FFFF')

    label = Label(SiteManual,text=globalV.siteManual_title_label,font='Calibri 14 bold', bg='#F0FFFF')
    label.place(relx=.015, rely=.0)
 
    label = Label(SiteManual,text=globalV.siteManual_siteName_label, font='Calibri 10 bold', bg='#F0FFFF')
    label.place(relx=.015, rely=.2)

    siteTxt = Text(SiteManual, width=21, height=1)
    siteTxt.place(relx=.24, rely=.2)
    siteTxt.focus_set() 

    cadastrarBtn = HoverButton(SiteManual,text=globalV.send_btn,  width=23, activebackground='#0688fa', bg='#2dabf9', command = lambda: CadastrarNovoSite(siteTxt.get("1.0","end-1c")))
    cadastrarBtn.place(relx=.015, rely=.4)

    SiteManual.bind('<KeyPress>', enterPressedSiteManual)

############################# Função para cadastrar novo Site manualmente #############################
def CadastrarNovoSite(siteName):
    siteParsed = siteName.rstrip().strip()
    
    if not siteParsed:
        siteTxt.focus_set()
        return messagebox.showinfo(globalV.siteName_text_empty_title, globalV.siteName_text_empty, parent=SiteManual)

    globalV.manual = True
    post_site_request('/organizations/{}/sites'.format(org_id), siteParsed)
    if code_access_token_site_post == 200:
        siteTxt.delete('1.0', END)
        siteTxt.focus_set()
        return messagebox.showinfo(globalV.success_title, globalV.siteManual_succesfully_registred + siteParsed, parent=SiteManual)
    elif code_access_token_site_post == 401 or code_access_token_site_post == 403:
        return messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_mgmt_default, parent=SiteManual)
    elif code_access_token_site_post == 404:
        return messagebox.showerror(globalV.invalid_orgID_title, globalV.invalid_orgID_default, parent=SiteManual)
    elif code_access_token_site_post == 409:
        siteTxt.delete('1.0', END)
        siteTxt.focus_set()
        return messagebox.showerror(globalV.siteManual_already_registred_title, globalV.siteManual_already_registred + siteParsed, parent=SiteManual)
    

############################# Janela Configuration File #############################
def openMenuConfigurationFile():  
    # Variavel global poist tem uso em outras funções
    global configFileWindow 

    # Criar a Janela via Toplevel e setar parametros iniciais
    configFileWindow = Toplevel(root)
    configFileWindow.title(globalV.configFile_title) 
    configFileWindow.wm_iconbitmap(iconImageFile)
    configFileWindow.minsize(470,100)
    center(configFileWindow)
    configFileWindow.resizable(0,0)
    configFileWindow.configure(background='#F0FFFF')

    file = open(configFilePath).read()
    t = Text(configFileWindow, width=70, height=5)
    t.pack()
    t.insert(0.0, file) 

    botao_salvar = HoverButton(configFileWindow,text=globalV.save_config_btn,  width=20, activebackground='#0688fa', bg='#2dabf9', command = lambda: save_configfile(t.get("1.0","end-1c")))
    botao_salvar.place(relx=.0, rely=.46)

    configFileWindow.protocol("WM_DELETE_WINDOW", on_closingConfig)


############################# Função para salvar o arquivo de configuração #############################
def save_configfile(self):
    f = open(configFilePath, "w")
    f.write(self)
    messagebox.showinfo(globalV.success_title, globalV.configuration_file_successfuly_saved)
    configFileWindow.destroy()
    

############################# Função para bindar quando pressionar a tecla Enter #############################
def enterPressedDestinations(e):
    if e.keycode == 13:
        start_progress_thread(None,progressbar_destination,"destination")

#Funcão para pegar o ID da lista de Destination selecionado e chamar a função de cadastro!
def CadastrarDestinations_SiteID():
    destinationIDselected = str(listaIdDestinations[cmbDestinations.current()]).rstrip()
    CadastrarDestination(destinationIDselected)

############################# Janela Destinations Lists #############################
def openMenuDestinationsList():   
    # Variavel global poist tem uso em outras funções
    global DestinationListsWindow,labelSelectedCSVDestination,cmbDestinations,listaIdDestinations,progressbar_destination
    # Criar a Janela via Toplevel e setar parametros iniciais
    DestinationListsWindow = Toplevel(root)   
    DestinationListsWindow.title(globalV.destinationCSV_title) 
    DestinationListsWindow.wm_iconbitmap(iconImageFile)
    DestinationListsWindow.minsize(400,200)
    center(DestinationListsWindow)
    DestinationListsWindow.resizable(0,0)
    DestinationListsWindow.configure(background='#F0FFFF')
    
    r_get_destinations = get_request('/organizations/{}/destinationlists'.format(org_id))

    #Fazer o get para pritar a lista de destinationslists e só proceder se estiver OK
    if code_access_token_getrequests == 200:
        #combobox dos Sites
        cmbDestinations = ttk.Combobox(DestinationListsWindow,state="readonly", width = 30)

        #Adicionar os names dos Sites ao combobox, e em seguida ja pegar seu id e jogar na lista de id_sites
        listaIdDestinations = []
        for sites in r_get_destinations['data']:
            cmbDestinations['value'] = (*cmbDestinations['values'], sites['name'])
            listaIdDestinations.append(sites['id'])

        labelprinc = Label(DestinationListsWindow,text=globalV.destinationCSV_title_label,font='Calibri 15 bold', bg='#F0FFFF')
        labelprinc.place(relx=.012, rely=.0)

        lablcsv = Label(DestinationListsWindow,text=globalV.label_choose_csv, font='Calibri 13 bold', bg='#F0FFFF')
        lablcsv.place(relx=.012, rely=.2)

        botao_csv = HoverButton(DestinationListsWindow,text=globalV.explore_csv_btn,  width=20, activebackground='#0688fa', bg='#2dabf9', command = lambda: browseDestination(False))
        botao_csv.place(relx=.30, rely=.2)

        labelSelectedCSVDestination = Label(DestinationListsWindow,text='', font='Calibri 12 bold', fg='#0ea3da', bg='#F0FFFF')
        labelSelectedCSVDestination.place(relx=.012, rely=.36)

        labeldest = Label(DestinationListsWindow,text=globalV.destination_list_assign_label, font='Calibri 13 bold', bg='#F0FFFF')
        labeldest.place(relx=.012, rely=.5)

        cmbDestinations.place(relx=.4, rely=.512)
        cmbDestinations.current(0) 
        #bindar para remover toda vez que fica selecionado, faz com que a janela fique com o foco
        cmbDestinations.bind("<<ComboboxSelected>>",lambda e: DestinationListsWindow.focus())

        progressbar_destination = ttk.Progressbar(DestinationListsWindow, style="bar.Horizontal.TProgressbar", orient="horizontal", length=150, mode="indeterminate")

        botao_enviar = HoverButton(DestinationListsWindow,text = globalV.send_btn,  width=20, activebackground='#0688fa', bg='#2dabf9', command = lambda:start_progress_thread(None,progressbar_destination,"destination"))
        botao_enviar.place(relx=.012, rely=.7)

        DestinationListsWindow.bind('<KeyPress>', enterPressedDestinations)
        DestinationListsWindow.protocol("WM_DELETE_WINDOW", on_closingDestination)

    elif code_access_token_getrequests == 401 or code_access_token_getrequests == 403:
        messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_mgmt_default, parent=DestinationListsWindow)
        on_closingDestination()
    elif code_access_token_getrequests == 404:
        messagebox.showerror(globalV.invalid_orgID_title, globalV.invalid_orgID_default, parent=DestinationListsWindow)
        on_closingDestination()

############################# Função para pegar o CSV de Destinations #############################
def load_csvDestination():
    # Lista para atribuir os dominios do CSV
    csv_urls = []
    try:
        # Tentando abrir o arquivo especificado
        with open(DestinationCSV) as csv_file_domain:
            csv_reader_domain = reader(csv_file_domain)

            # Adicionar cada dominio na lista de csv_urls
            for domain in csv_reader_domain:
                csv_urls.append(domain[0])
            return csv_urls
    except:
        return "NotCSV"

############################# Ação do botão para cadastrar Destinations via CSV #############################
def CadastrarDestination(destination_id):
    # Fazer o load do CSV para checar se foi selecionado
    checkCSV = load_csvDestination()
    successDestinations = ""
    DestinationListsWindow.focus_set()
    if checkCSV == "NotCSV":
        clearDestination()
        return messagebox.showinfo(globalV.csv_missing_title, globalV.csv_missing, parent=DestinationListsWindow)     
    
    #chama função pra checar as colunas do CSV
    check = checkCSVColumns(DestinationCSV, 'destination')
    if check == "wrongCSV":
        clearDestination()
        return messagebox.showinfo(globalV.wrong_csv_title, globalV.wrong_csv, parent=DestinationListsWindow) 

    new_urls_destinations = []
    new_urls_destinations += load_csvDestination()

    # fazer o get das internal netwokrs para comparar com o vsv
    r_get_destinations = get_request('/organizations/{}/destinationlists/{}/destinations'.format(org_id,destination_id)) 

    
    #Só procede o GET se for Status ok (200), se não informar o que esta errado
    if code_access_token_getrequests == 200:
        lista_exist_umbrella = []

        #Adicionar do Umbrella Internal Domains a uma lista
        for internadomail in r_get_destinations['data']:
            lista_exist_umbrella.append(internadomail['destination'])

        #Remover duplicados no CSV
        new_urls_destinations = list(dict.fromkeys(new_urls_destinations))
        
        # Remover da lista o que já esta cadastrado no Umbrella
        new_urls_destinations = list(set(new_urls_destinations) - set(lista_exist_umbrella))
        
        #Se a lista retornar vazia não cadastrar nada
        if not new_urls_destinations:
            clearDestination()
            return messagebox.showinfo(globalV.csv_already_registred_title, globalV.csv_already_registred + fileNameCSV_Destination, parent=DestinationListsWindow)

        globalV.manual = False 
        for cadastrar in new_urls_destinations:
            post_destinations_request('/organizations/{}/destinationlists/{}/destinations'.format(org_id,destination_id), cadastrar)
            time.sleep(tempo) #Começar o progressbar e quando terminar os eventos vão ser gerados lá
            successDestinations += cadastrar + "\n"
        
        if code_access_token_destination_post == 200:
            clearDestination()
            if not os.path.isfile(fullFolderLogsPath +'/registred_destinations.log'):
                f = open(fullFolderLogsPath + "/registred_destinations.log", "x")
                f.close()
            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            f = open(fullFolderLogsPath + "/registred_destinations.log", "a")
            f.write("--------------------------------------------------")
            f.write("\n")
            f.write(str(dt_string))
            f.write("\n")
            f.write(globalV.destination_log)
            f.write("\n") 
            f.write("\n")
            f.write(successDestinations)
            f.close()
            return messagebox.showinfo(globalV.destination_successfully_registred_title, globalV.destination_successfully_registred_title, parent=DestinationListsWindow)
        elif code_access_token_destination_post == 401 or code_access_token_destination_post == 403:
            return messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_mgmt_default, parent=DestinationListsWindow)
        elif code_access_token_destination_post == 404:
            return messagebox.showerror(globalV.invalid_orgID_title, globalV.invalid_orgID_default, parent=DestinationListsWindow)
    elif code_access_token_getrequests == 401 or code_access_token_getrequests == 403:
        return messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_mgmt_default, parent=DestinationListsWindow)
    elif code_access_token_getrequests == 404:
        return messagebox.showerror(globalV.invalid_orgID_title, globalV.invalid_orgID_default, parent=DestinationListsWindow)

############################# Função para bindar quando pressionar a tecla Enter #############################
def enterPressedInternalNet(e):
    if e.keycode == 13:
        start_progress_thread(None, progressbar_net, "internalnet")

#Funcão para pegar o SiteID do Site selecionado e chamar a função de cadastro!
def CadastrarInternalNet_SiteID():
    siteIDselected = str(listaIdSites[cmbSites.current()]).rstrip()
    CadastrarInternalNet(siteIDselected)

############################# Janela Internal Networks #############################
def openMenuInternalNetworks():   
    # Variavel global poist tem uso em outras funções
    global internalnetWindow,labelSelectedCSVNet,cmbSites,listaIdSites,progressbar_net
    # Criar a Janela via Toplevel e setar parametros iniciais
    internalnetWindow = Toplevel(root)   
    internalnetWindow.title(globalV.internalnetworks_title) 
    internalnetWindow.wm_iconbitmap(iconImageFile)
    internalnetWindow.minsize(400,200)
    center(internalnetWindow)
    internalnetWindow.resizable(0,0)
    internalnetWindow.configure(background='#F0FFFF')
    
    r_get_sites = get_request('/organizations/{}/sites'.format(org_id))


    #Fazer o get para pritar a lista de sites e só proceder se estiver OK
    if code_access_token_getrequests == 200:
        dump_sites = json.dumps(r_get_sites)
        sites_json = json.loads(dump_sites)
        #combobox dos Sites
        cmbSites = ttk.Combobox(internalnetWindow,state="readonly", width = 30)

        #Adicionar os names dos Sites ao combobox, e em seguida ja pegar seu id e jogar na lista de id_sites
        listaIdSites = []
        for sites in sites_json:
            cmbSites['value'] = (*cmbSites['values'], sites['name'])
            listaIdSites.append(sites['siteId'])

        labelprinc = Label(internalnetWindow,text=globalV.internalnetworks_title_label,font='Calibri 15 bold', bg='#F0FFFF')
        labelprinc.place(relx=.012, rely=.0)

        lablcsv = Label(internalnetWindow,text=globalV.label_choose_csv, font='Calibri 13 bold', bg='#F0FFFF')
        lablcsv.place(relx=.012, rely=.2)

        botao_csv = HoverButton(internalnetWindow,text=globalV.explore_csv_btn,  width=20, activebackground='#0688fa', bg='#2dabf9', command = lambda: browseInternalNet(False))
        botao_csv.place(relx=.30, rely=.2)

        labelSelectedCSVNet = Label(internalnetWindow,text='', font='Calibri 12 bold', fg='#0ea3da', bg='#F0FFFF')
        labelSelectedCSVNet.place(relx=.012, rely=.36)

        labelSite = Label(internalnetWindow,text=globalV.internalnetworks_site_assign_label, font='Calibri 13 bold', bg='#F0FFFF')
        labelSite.place(relx=.012, rely=.5)

        cmbSites.place(relx=.43, rely=.512)
        cmbSites.current(0) 
        #bindar para remover toda vez que fica selecionado, faz com que a janela fique com o foco
        cmbSites.bind("<<ComboboxSelected>>",lambda e: internalnetWindow.focus())

        progressbar_net = ttk.Progressbar(internalnetWindow, style="bar.Horizontal.TProgressbar", orient="horizontal", length=150, mode="indeterminate")
        
        botao_enviar = HoverButton(internalnetWindow,text = globalV.send_btn,  width=20, activebackground='#0688fa', bg='#2dabf9', command = lambda:start_progress_thread(None, progressbar_net, "internalnet"))
        botao_enviar.place(relx=.012, rely=.7)

    
        internalnetWindow.bind('<KeyPress>', enterPressedInternalNet)
        internalnetWindow.protocol("WM_DELETE_WINDOW", on_closingNet)

    elif code_access_token_getrequests == 401 or code_access_token_getrequests == 403:
        messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_mgmt_default, parent=internalnetWindow)
        on_closingNet()
    elif code_access_token_getrequests == 404:
        messagebox.showerror(globalV.invalid_orgID_title, globalV.invalid_orgID_default, parent=internalnetWindow)
        on_closingNet()

############################# Função para pegar o CSV de Internal Domains #############################    
def load_csvInternalNet():
    try:
        # Tentando abrir o arquivo especificado
        with open(internalNetCSV):
            pass
    except:
        return "NotCSV"

############################# Ação do botão para cadastrar Internal Networks via CSV #############################
def CadastrarInternalNet(siteId):
    #Fazer o Load do CSV de Internal Networks para checar
    checkCSV = load_csvInternalNet()
    if checkCSV == "NotCSV":
        clearInternalNet()
        return messagebox.showinfo(globalV.csv_missing_title, globalV.csv_missing, parent=internalnetWindow)
    
      
    
    # fazer o get das internal netwokrs para comparar com o vsv
    r_get_internalnet = get_request('/organizations/{}/internalnetworks'.format(org_id))

    #Só procede o GET se for Status ok (200), se não informar o que esta errado
    if code_access_token_getrequests == 200:
        #Variavel para concatenar as Internal Networks para depois logar como sucedidas
        successinternalNetworks = ""

        #Tratar json de r_get_internalnet
        dump_actual_internalnet = json.dumps(r_get_internalnet)
        act_internal_net = json.loads(dump_actual_internalnet)
        
        # remover do json act_internal_net o que nao importa comparar
        for element in act_internal_net: 
            del element['originId']
            del element['siteName']
            del element['createdAt']
            del element['modifiedAt']
            del element['siteId']
 
        # Abrir o CSV se existe'
        f = open(internalNetCSV, 'r',encoding='utf-8-sig')  

        # Adicionar as colunas no output do CSV Principal para ficar igual JSON pra post.
        readerDic = DictReader(f, delimiter=',', fieldnames = ("name","ipAddress","prefixLength")) 
    
        #Odernar o Csv para nao ter problemas futuros no umbrela  
        sorted_csv = sorted(readerDic, key=lambda row: (row['name']))
    
        #chama função pra checar as colunas do CSV
        check = checkCSVColumns(internalNetCSV, 'internalnet')
        if check == "wrongCSV":
            clearInternalNet()
            return messagebox.showinfo(globalV.wrong_csv_title, globalV.wrong_csv, parent=internalnetWindow) 

        
        # Fazer o Parse de CSV para JSON  
        dump_new_internalnet = json.dumps( [ row for row in sorted_csv ])  
        new_internalnet = json.loads(dump_new_internalnet)
        count = 0
        for net in new_internalnet:
            check = checkValidIpNetwork(net['ipAddress'] + "/" + net['prefixLength'], net['name'])
            if check == False:
                count+=1
            else:
                pass

        #Se achar alguma linha do CSV com IP errado pausar, nao deixa seguir com cadastro
        if count > 0:
            clearInternalNet()
            return messagebox.showerror(globalV.invalid_ip__message_title, globalV.invalid_ip_message, parent=internalnetWindow)
        
        #Remover duplicados exatos do csv e criar nova lista adionando somente o que não é duplicado
        lista_removido_duplicado = []
        for item in removeduplicate(new_internalnet):
            lista_removido_duplicado.append(item)
        
        #Remover nomes iguais dentro da lista de removido_duplicado, pois se tem mais de um nome igual já no csv, mantem o primeiro e remove o resto
        lista_final_new = list()
        items_set = set()    
        for js in lista_removido_duplicado:
            # só adiciona items nao vistos (referenciando to 'nome' como key)
            if not js['name'] in items_set:
                # marcar como seen
                items_set.add(js['name'])         
                # add to results
                lista_final_new.append(js)

        #Remover Ip/prefix iguais dentro da lista de removido_duplicado, pois se tem mais de um um ip/prefix igual já no csv, mantem o primeiro e remove o resto
        lista_final = list()
        items_set_ip = set()
        for ip in lista_final_new:
            # só adiciona items nao vistos (referenciando to 'ipddress/prefix' como key)
            ipnet = ip['ipAddress'] + "/" + str(ip['prefixLength'])
            if not ipnet in items_set_ip:
                # marcar como seen
                items_set_ip.add(ipnet)          
                # adciona a lista final
                lista_final.append(ip)

        #Comparar o nome e ippadress que tem no CSV com o que já tem no Umbrella, e cadastrar só os que nao tem! 
        #As comparações anteriores foram todas para o arquivos do CSV, ou seja, localmente
        for k in range(len(act_internal_net)):
            for i in range(len(lista_final)):
                ipatual = act_internal_net[k]['ipAddress'] + "/" + str(act_internal_net[k]['prefixLength'])
                ipnovo =  lista_final[i]['ipAddress'] + "/" + str(lista_final[i]['prefixLength'])
                if (act_internal_net[k]["name"] == lista_final[i]['name'] or ipatual == ipnovo):
                    lista_final.pop(i)              
                    break   
        
        #Se a lista retornar vazia não cadastrar nada
        if not lista_final:
            clearInternalNet()
            return messagebox.showinfo(globalV.csv_already_registred_title, globalV.csv_already_registred + fileNameCSV_InternalNetwork, parent=internalnetWindow)
        total = 0
        for cadastrar in lista_final:
            #Adiciona o siteID criado ao final da lista Json que vai mandar o POST
            cadastrar['siteId'] = int(siteId)
            post_internalnetworks_request('/organizations/{}/internalnetworks'.format(org_id), json.dumps(cadastrar)) 
            total += tempo
            successinternalNetworks += "Intenal Network: " + cadastrar['name'] + ", Ip/Prefix: " + cadastrar['ipAddress'] + "/" + cadastrar['prefixLength']  + "\n"
        
        if code_access_token_net_post == 200:
            clearInternalNet()
            now = datetime.now()
            # dd/mm/YY H:M:S
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            if not os.path.isfile(fullFolderLogsPath + '/registred_internalNetworks.log'):
                f = open(fullFolderLogsPath + "/registred_internalNetworks.log", "x")
                f.close()
            f = open(fullFolderLogsPath + "/registred_internalNetworks.log", "a")
            f.write("--------------------------------------------------")
            f.write("\n")
            f.write(str(dt_string) + "    " + globalV.internalnetworks_timereg + str(round(total*5,2)))
            f.write("\n")
            f.write(globalV.internalnetworks_log)
            f.write("\n") 
            f.write("\n")
            f.write(successinternalNetworks)
            f.close()
            return messagebox.showinfo(globalV.internalnetworks_successfully_registred_title, globalV.internalnetworks_successfully_registred, parent=internalnetWindow)
        elif code_access_token_net_post == 401 or code_access_token_net_post == 403:
            return messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_mgmt_default, parent=internalnetWindow)
        elif code_access_token_net_post == 404:
            return messagebox.showerror(globalV.invalid_orgID_title, globalV.invalid_orgID_default, parent=internalnetWindow)
        elif code_access_token_net_post == 400:
            return messagebox.showerror("SiteID inválido", "SiteID inválido, por favor informe um SiteID válido", parent=internalnetWindow)
    elif code_access_token_getrequests == 401 or code_access_token_getrequests == 403:
        return messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_mgmt_default, parent=internalnetWindow)
    elif code_access_token_getrequests == 404:
        return messagebox.showerror(globalV.invalid_orgID_title, globalV.invalid_orgID_default, parent=internalnetWindow)
        
############################# Função para bindar quando pressionar a tecla Enter #############################
def enterPressedInternalDomain(e):
    if e.keycode == 13:
        start_progress_thread(None, progressbar_domain, "domain")

############################# Janela Internal Domains #############################
def openMenuInternalDomains():   
    # Variavel global poist tem uso em outras funções
    global internaldomainWindow,progressbar_domain,labelSelectedCSVDomain
    
    # Criar a Janela via Toplevel e setar parametros iniciais
    internaldomainWindow = Toplevel(root) 
    internaldomainWindow.title(globalV.internaldomainCSV_title) 
    internaldomainWindow.wm_iconbitmap(iconImageFile)
    internaldomainWindow.minsize(400,50)
    center(internaldomainWindow)
    internaldomainWindow.resizable(0,0)
    internaldomainWindow.configure(background ='#F0FFFF')
    

    labelTitle = Label(internaldomainWindow,text=globalV.internaldomainCSV_title_label,font='Calibri 15 bold', bg='#F0FFFF')
    labelTitle.place(relx=.015,rely=.0)

    label = Label(internaldomainWindow,text=globalV.label_choose_csv, font='Calibri 13 bold', bg='#F0FFFF')
    label.place(relx=.015,rely=.17)

    labelSelectedCSVDomain = Label(internaldomainWindow,text='',font='Calibri 12 bold', fg = '#0ea3da', bg='#F0FFFF')
    labelSelectedCSVDomain.place(relx=.015,rely=.32)

    botao_csv = HoverButton(internaldomainWindow,text=globalV.explore_csv_btn,  width=20, activebackground='#0688fa', bg='#2dabf9', command = lambda: browseInternalDomains(False))
    botao_csv.place(relx=.29, rely=.17)

    progressbar_domain = ttk.Progressbar(internaldomainWindow, style="bar.Horizontal.TProgressbar", orient="horizontal", length=150, mode="indeterminate")

    botao_enviar = HoverButton(internaldomainWindow,text = globalV.send_btn,  width=20, activebackground='#0688fa', bg='#2dabf9', command = lambda:start_progress_thread(None, progressbar_domain, "domain"))
    botao_enviar.place(relx=.015, rely=.45)

    internaldomainWindow.bind('<KeyPress>', enterPressedInternalDomain)
    internaldomainWindow.protocol("WM_DELETE_WINDOW", on_closingDomain)

    
############################# Função para pegar o CSV de Internal Domains #############################
def load_csvInternalDomains():
    # Lista para atribuir os dominios do CSV
    csv_domains = []
    try:
        # Tentando abrir o arquivo especificado
        with open(internaldomainCSV) as csv_file_domain:
            csv_reader_domain = reader(csv_file_domain)

            # Adicionar cada dominio na lista de csv_domains
            for domain in csv_reader_domain:
                csv_domains.append(domain[0])
            return csv_domains
    except:
        return "NotCSV"

############################# Ação do botão para cadastrar Internal Domains via CSV #############################
def CadastrarInternalDomains():
    # Fazer o load do CSV para checar se foi selecionado
    checkCSV = load_csvInternalDomains()
    successinternalDomains = ""
    internaldomainWindow.focus_set()
    if checkCSV == "NotCSV":
        clearInternalDomain()
        return messagebox.showinfo(globalV.csv_missing_title, globalV.csv_missing, parent=internaldomainWindow)

    #chama função pra checar as colunas do CSV
    check = checkCSVColumns(internaldomainCSV, 'domain')
    if check == "wrongCSV":
        clearInternalDomain()
        return messagebox.showinfo(globalV.wrong_csv_title, globalV.wrong_csv, parent=internaldomainWindow) 

    new_internaldomains = []
    new_internaldomains += load_csvInternalDomains()

    # fazer o get das internal netwokrs para comparar com o vsv
    r_get_internaldomain = get_request('/organizations/{}/internaldomains'.format(org_id)) 

    #Só procede o GET se for Status ok (200), se não informar o que esta errado
    if code_access_token_getrequests == 200:
        lista_exist_umbrella = []

        #Adicionar do Umbrella Internal Domains a uma lista
        for internadomail in r_get_internaldomain:
            lista_exist_umbrella.append(internadomail['domain'])

        #Remover duplicados no CSV
        new_internaldomains = list(dict.fromkeys(new_internaldomains))
        
        # Remover da lista o que já esta cadastrado no Umbrella
        new_internaldomains = list(set(new_internaldomains) - set(lista_exist_umbrella))
        
        #Se a lista retornar vazia não cadastrar nada
        if not new_internaldomains:
            clearInternalDomain()
            return messagebox.showinfo(globalV.csv_already_registred_title, globalV.csv_already_registred + fileNameCSV_InternalDomain, parent=internaldomainWindow) 
        
        globalV.manual = False
        for cadastrar in new_internaldomains:        
            post_internaldomains_request('/organizations/{}/internaldomains'.format(org_id), cadastrar)
            time.sleep(tempo) #Começar o progressbar e quando terminar os eventos vão ser gerados lá
            successinternalDomains += cadastrar + "\n"
    
        if code_access_token_domains_post == 200:
            clearInternalDomain()
            if not os.path.isfile(fullFolderLogsPath +'/registred_domains.log'):
                f = open(fullFolderLogsPath + "/registred_domains.log", "x")
                f.close()
            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            f = open(fullFolderLogsPath + "/registred_domains.log", "a")
            f.write("--------------------------------------------------")
            f.write("\n")
            f.write(str(dt_string))
            f.write("\n")
            f.write(globalV.internaldomain_log)
            f.write("\n") 
            f.write("\n")
            f.write(successinternalDomains)
            f.close()
            return messagebox.showinfo(globalV.internaldomain_successfully_registred_title, globalV.internaldomain_successfully_registred, parent=internaldomainWindow)
        elif code_access_token_domains_post == 401 or code_access_token_domains_post == 403:
            return messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_mgmt_default, parent=internaldomainWindow)
        elif code_access_token_domains_post == 404:
            return messagebox.showerror(globalV.invalid_orgID_title, globalV.invalid_orgID_default, parent=internaldomainWindow)
    elif code_access_token_getrequests == 401 or code_access_token_getrequests == 403:
        return messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_mgmt_default, parent=internaldomainWindow)
    elif code_access_token_getrequests == 404:
        return messagebox.showerror(globalV.invalid_orgID_title, globalV.invalid_orgID_default, parent=internaldomainWindow)

#Função para bindar quando pressionar a tecla Enter
def enterPressedSite(e):
    if e.keycode == 13:
        start_progress_thread(None, progressbar_site, "site")

############################# Janela Sites ############################# 
def openMenuSitesCSV():   
    # Variavel global poist tem uso em outras funções
    global SitesCSVWindow,labelSelectedCSVSite,progressbar_site
    
    # Criar a Janela via Toplevel e setar parametros iniciais
    SitesCSVWindow = Toplevel(root) 
    SitesCSVWindow.title(globalV.sitesCSV_title) 
    SitesCSVWindow.wm_iconbitmap(iconImageFile)
    SitesCSVWindow.minsize(400,50)
    center(SitesCSVWindow)
    SitesCSVWindow.resizable(0,0)   
    SitesCSVWindow.configure(background = '#F0FFFF')

    labelTitle = Label(SitesCSVWindow,text=globalV.sitesCSV_title_label,font='Calibri 15 bold', bg='#F0FFFF')
    labelTitle.place(relx=.015,rely=.0)

    label = Label(SitesCSVWindow,text=globalV.label_choose_csv, font='Calibri 13 bold', bg='#F0FFFF')
    label.place(relx=.015,rely=.17)

    labelSelectedCSVSite = Label(SitesCSVWindow,text='',font='Calibri 12 bold', fg ='#0ea3da', bg='#F0FFFF')
    labelSelectedCSVSite.place(relx=.015,rely=.32)

    botao_csv = HoverButton(SitesCSVWindow,text=globalV.explore_csv_btn,  width=20, activebackground='#0688fa', bg='#2dabf9', command = lambda: browseSitesCSV(False))
    botao_csv.place(relx=.29, rely=.17)

    progressbar_site = ttk.Progressbar(SitesCSVWindow, style="bar.Horizontal.TProgressbar", orient="horizontal", length=150, mode="indeterminate")
    
    botao_enviar = HoverButton(SitesCSVWindow,text = globalV.send_btn,  width=20, activebackground='#0688fa', bg='#2dabf9', command = lambda:start_progress_thread(None, progressbar_site, "site"))
    botao_enviar.place(relx=.015, rely=.45)
  
    
    SitesCSVWindow.bind('<KeyPress>', enterPressedSite)
    SitesCSVWindow.protocol("WM_DELETE_WINDOW", on_closingSitesCSV)


############################# Função para pegar o CSV de Sites #############################
def load_csvSites():
    # Lista para atribuir os dominios do CSV
    csv_sites = []
    try:
        # Tentando abrir o arquivo especificado
        with open(SitesCSV) as csv_file_sites:
            csv_reader_site = reader(csv_file_sites)  
            # Adicionar cada dominio na lista de csv_domains
            for site in csv_reader_site:
                csv_sites.append(site[0])
            return csv_sites
    except:
        return "NotCSV"


############################# Ação do botão para cadastrar Sites via CSV  #############################
def CadastrarSitesCSV():
    #Fazer o load do CSV para verificar se foi selecionado
    global successSites
    checkCSV = load_csvSites()
    successSites = ""
    SitesCSVWindow.focus_set()
    if checkCSV == "NotCSV":
        clearSite()
        return messagebox.showinfo(globalV.csv_missing_title, globalV.csv_missing, parent=SitesCSVWindow)
        
    
    check = checkCSVColumns(SitesCSV, 'sites')
    if check == "wrongCSV":
        clearSite()
        return messagebox.showinfo(globalV.wrong_csv_title, globalV.wrong_csv, parent=SitesCSVWindow)
    
    new_sites = []
    new_sites += load_csvSites()

    # fazer o get das internal netwokrs para comparar com o vsv
    r_get_sites = get_request('/organizations/{}/sites'.format(org_id))     

    #Só procede o GET se for Status ok (200), se não informar o que esta errado
    if code_access_token_getrequests == 200:    
        listaSites_exist_umbrella = []

        #Adicionar do Umbrella Internal Domains a uma lista
        for site in r_get_sites:
            listaSites_exist_umbrella.append(site['name'])

        #Remover duplicados no CSV
        new_sites = list(dict.fromkeys(new_sites))
        
        # Remover da lista o que já esta cadastrado no Umbrella
        new_sites = list(set(new_sites) - set(listaSites_exist_umbrella))
        
        #Se a lista retornar vazia não cadastrar nada
        if not new_sites:
            clearSite()
            return messagebox.showinfo(globalV.csv_already_registred_title, globalV.csv_already_registred + fileNameCSV_Sites, parent=SitesCSVWindow)

        globalV.manual = False
        for cadastrarSites in new_sites:    
            post_site_request('/organizations/{}/sites'.format(org_id), cadastrarSites)
            time.sleep(tempo) #Começar o progressbar e quando terminar os eventos vão ser gerados lá
            successSites += "Site: " + cadastrarSites + "\n"

        if code_access_token_site_post == 200:
            clearSite()
            if not os.path.isfile(fullFolderLogsPath + '/registred_sites.log'):
                f = open(fullFolderLogsPath+ "/registred_sites.log", "x")
                f.close()
            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            f = open(fullFolderLogsPath + "/registred_sites.log", "a")
            f.write("--------------------------------------------------")
            f.write("\n")
            f.write(str(dt_string))
            f.write("\n")
            f.write(globalV.sites_log)
            f.write("\n")
            f.write("\n")
            f.write(successSites)
            f.close()
            return messagebox.showinfo(globalV.sites_successfully_registred_title, globalV.sites_successfully_registred, parent=SitesCSVWindow)
        elif code_access_token_site_post == 401 or code_access_token_site_post == 403:
            return messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_mgmt_default, parent=SitesCSVWindow)
        elif code_access_token_site_post == 404:
            return messagebox.showerror(globalV.invalid_orgID_title, globalV.invalid_orgID_default, parent=SitesCSVWindow)
    elif code_access_token_getrequests == 401 or code_access_token_getrequests == 403:
        return messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_mgmt_default, parent=SitesCSVWindow)
    elif code_access_token_getrequests == 404:
        return messagebox.showerror(globalV.invalid_orgID_title, globalV.invalid_orgID_default, parent=SitesCSVWindow)

     

############################# Função para centralizar as Windows #############################
def center(win):
    win.update_idletasks()
    width = win.winfo_width()
    frm_width = win.winfo_rootx() - win.winfo_x()
    win_width = width + 2 * frm_width
    height = win.winfo_height()
    titlebar_height = win.winfo_rooty() - win.winfo_y()
    win_height = height + titlebar_height + frm_width
    x = win.winfo_screenwidth() // 2 - win_width // 2
    y = win.winfo_screenheight() // 2 - win_height // 2
    win.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    win.deiconify()


############################# Função para definir imagens de background do TopLevel do Menu Pricipal #############################
def backgroundImage(win):
    IMAGE_PATH = backgroundImageFile
    WIDTH, HEIGTH = win.winfo_width(), win.winfo_height()

    canvas = Canvas(win, width=WIDTH, height=HEIGTH)
    canvas.pack()

    img = ImageTk.PhotoImage(Image.open(IMAGE_PATH).resize((WIDTH, HEIGTH), Image.ANTIALIAS))
    canvas.background = img
    canvas.create_image(0, 0, anchor=NW, image=img)
    

############################# Menu Principal #############################
def menu():
    global MenuPrincipal
    MenuPrincipal = Toplevel(root)
    menubar = Menu(MenuPrincipal,background='#0ea3da', foreground='black', activebackground='#004c99', activeforeground='white') 
    MenuPrincipal.config(menu=menubar)
    
    #Menubar Cadastrar Sites    
    filemenu = Menu(menubar, tearoff=0, background='white', foreground='#000000')
    filemenu.add_separator()
    filemenu.add_command(label=globalV.menu_sites_csv, command=openMenuSitesCSV)
    filemenu.add_command(label=globalV.menu_sites_manual, command=openMenuSiteManual)
    menubar.add_cascade(label=globalV.menu_sites, menu=filemenu)

    #Menubar Cadastrar Internal Networks
    filemenu2 = Menu(menubar, tearoff=0, background='white', foreground='#000000')  
    filemenu2.add_separator()
    filemenu2.add_command(label=globalV.menu_internalNetworks_csv, command=openMenuInternalNetworks)
    menubar.add_cascade(label=globalV.menu_internalNetworks, menu=filemenu2)

    #Menubar Cadastrar Internal Domains
    filemenu3 = Menu(menubar, tearoff=0, background='white', foreground='#000000') 
    filemenu3.add_separator()
    filemenu3.add_command(label=globalV.menu_domain_csv, command=openMenuInternalDomains)
    filemenu3.add_command(label=globalV.menu_domain_manual, command=openMenuDomainManual)
    menubar.add_cascade(label=globalV.menu_domain, menu=filemenu3)

    #Menubar Cadastro de blocklist e whitelist
    filemenu4 = Menu(menubar, tearoff=0, background='white', foreground='#000000') 
    filemenu4.add_separator()
    filemenu4.add_command(label=globalV.menu_destinations_csv, command=openMenuDestinationsList)
    filemenu4.add_command(label=globalV.menu_destinations_manual, command=openMenuDestinationManual)
    menubar.add_cascade(label=globalV.menu_policy_components, menu=filemenu4)

    #Menubar Umbrella Investigate
    filemenu5 = Menu(menubar, tearoff=0, background='white', foreground='#000000') 
    filemenu5.add_separator()
    filemenu5.add_command(label=globalV.investigate_menu_title, command=openInvestigate)
    menubar.add_cascade(label=globalV.investigate_title, menu=filemenu5)

    #Menubar Umbrella Reporting
    filemenu6 = Menu(menubar, tearoff=0, background='white', foreground='#000000') 
    filemenu6.add_separator()
    filemenu6.add_command(label=globalV.reporting_menu_title, command=openMenuReporting)
    menubar.add_cascade(label=globalV.reporting_title, menu=filemenu6)

    
    #Menu Arquvivo de configuração
    filemenu7 = Menu(menubar, tearoff=0, background='white', foreground='#000000')
    filemenu7.add_separator()
    filemenu7.add_command(label=globalV.menu_configFile, command=openMenuConfigurationFile)
    menubar.add_cascade(label=globalV.menu_configFile_title, menu=filemenu7)
    
    #Menubar Sair
    filemenu8 = Menu(menubar, tearoff=0, background='white', foreground='#000000')
    filemenu8.add_separator()
    filemenu8.add_command(label=globalV.menu_exit, command=on_closingMenu)
    menubar.add_cascade(label=globalV.menu_exit, menu=filemenu8)

    MenuPrincipal.wm_iconbitmap(iconImageFile)
    MenuPrincipal.title('Cisco Umbrella API Calls - {}'.format(versao))
    MenuPrincipal.minsize(900,350)
    MenuPrincipal.resizable(0,0)
    center(MenuPrincipal)
    backgroundImage(MenuPrincipal)
    MenuPrincipal.protocol("WM_DELETE_WINDOW", on_closingMenu)


############################# Classe para fazer os MouseHover nos buttons #############################
class HoverButton(Button):
    def __init__(self, master, **kw):
        Button.__init__(self,master=master,**kw)
        self.defaultBackground = self["background"]
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)

    def on_enter(self, e):
        self['background'] = self['activebackground']

    def on_leave(self, e):
        self['background'] = self.defaultBackground


############################# Função para bindar quando pressionar a tecla Enter #############################
def enterPressed(e):
    if e.keycode == 13:
        VerificaEmail(emailTxt.get("1.0","end-1c").rstrip())


############################# Função para verificação do email, se for um full admin tem acesso a aplicação #############################
def VerificaEmail(email):
    if email == "":
        emailTxt.focus_set()
        return messagebox.showwarning(globalV.texto_acesso_negadoTitulo_root, globalV.empty_email_text, parent=root)

    LerConfiguracao()
    r_users = get_request('/organizations/{}/users'.format(org_id)) 
    #Só procede o GET se for Status ok (200), se não informar o que esta errado
    if code_access_token_getrequests == 200: 
        userEmail = []
        for u in r_users:
            if u['role'] == "Full Admin":
                userEmail.append(u['email'])
        if email in userEmail:
            menu()
            root.withdraw()
        else: 
            emailTxt.delete('1.0', END)
            emailTxt.focus_set()
            return messagebox.showerror(globalV.texto_acesso_negadoTitulo_root, globalV.texto_acesso_negado_root + email, parent=root)   
    elif code_access_token_getrequests == 404:
        messagebox.showerror(globalV.invalid_orgID_title, globalV.invalid_orgID_verify_email, parent=root)
        set_value_in_property_file(configFilePath, 'Umbrella', 'organization_id', '<Organization ID>')
        emailTxt.delete('1.0', END)
        FirstTimeScript()
    elif code_access_token_getrequests == 401 or code_access_token_getrequests == 403:
        messagebox.showerror(globalV.invalid_mgmt_title_verify_email, globalV.invalid_mgmt_verify_email, parent=root)
        set_value_in_property_file(configFilePath, 'Umbrella', 'management_api_key', '<Umbrella Management API Key>')
        set_value_in_property_file(configFilePath, 'Umbrella', 'management_secret_key', '<Umbrella Management Secret Key>')
        emailTxt.delete('1.0', END)
        FirstTimeScript()

############################# Função para abrir URL de informação #############################
def AbreURL(url):
    webbrowser.open(url, new=2)

############################# Setar linguagem #############################
def SetLang(lang, default):
    root.focus()
    lang.lower()
    lang_str = unidecode(lang)
    
    #Variavel default é pra saber se muda o valor na configuração, se for rodando o script sem escolher a linguagem nao precisa mudar
    if default == False:
        set_value_in_property_file(configFilePath, 'Language', 'lang', lang_str)
        
        #Reiniciar script com linguagem nova
        #os.execv(sys.executable, ['python'] + sys.argv)
        os.execl(sys.executable, sys.executable, *sys.argv)

    with open(fullFolderTranslationsPath +'/frases_' + lang_str + '.json', encoding='utf-8-sig') as frase:
        frases= json.load(frase)
    
    for i in frases['frase']:
        globalV.texto_acesso_negadoTitulo_root = i['invalid_access_title']
        globalV.texto_acesso_negado_root = i['invalid_access']
        globalV.texto_label_linguagem_root = i['label_language']
        globalV.title_label_root = i['root_title_label']
        globalV.title_root = i['root_title']
        globalV.access_btn_root= i['access_btn']
        globalV.firstTimeScript_message = i['firstTimeScript_message']
        globalV.firstTimeScript_message_title = i['firstTimeScript_message_title']
        globalV.firstTimeScript_ask_mgm_secret = i['firstTimeScript_ask_mgm_secret']
        globalV.firstTimeScript_ask_mgm_key = i['firstTimeScript_ask_mgm_key']
        globalV.firstTimeScript_ask_orgID = i['firstTimeScript_ask_orgID']
        globalV.firstTimeScript_ask_investigate_key = i['firstTimeScript_ask_investigate_key']
        globalV.firstTimeScript_ask_reporting_key = i['firstTimeScript_ask_reporting_key']
        globalV.firstTimeScript_ask_reporting_secret = i['firstTimeScript_ask_reporting_secret']
        globalV.firstTimeScript_empty_orgID = i['firstTimeScript_empty_orgID']
        globalV.firstTimeScript_empty_orgID_title = i['firstTimeScript_empty_orgID_title']
        globalV.firstTimeScript_empty_mgmg_key = i['firstTimeScript_empty_mgmg_key']
        globalV.firstTimeScript_empty_mgmg_key_title  = i['firstTimeScript_empty_mgmg_key_title']
        globalV.firstTimeScript_empty_secret_key = i['firstTimeScript_empty_secret_key']
        globalV.firstTimeScript_empty_secret_key_title = i['firstTimeScript_empty_secret_key_title']
        globalV.firstTimeScript_empty_investigate_key_title = i['firstTimeScript_empty_investigate_key_title']
        globalV.firstTimeScript_empty_investigate_key = i['firstTimeScript_empty_investigate_key']
        globalV.firstTimeScript_empty_reporting_secret_key_title = i['firstTimeScript_empty_reporting_secret_key_title']
        globalV.firstTimeScript_empty_reporting_secret_key = i['firstTimeScript_empty_reporting_secret_key']
        globalV.firstTimeScript_empty_reporting_key_title = i['firstTimeScript_empty_reporting_key_title']
        globalV.firstTimeScript_empty_reporting_key = i['firstTimeScript_empty_reporting_key']
        globalV.firstTimeScript_ask_titles = i['firstTimeScript_ask_titles']
        globalV.fileDiaglog_explorer = i['fileDiaglog_explorer']
        globalV.configuration_file_successfuly_saved = i['configuration_file_successfuly_saved']
        globalV.configuration_file_successfuly_saved_title = i['configuration_file_successfuly_saved_title']
        globalV.save_config_btn = i['save_config_btn']
        globalV.configFile_title = i['configFile_title']
        globalV.send_btn = i['send_btn']
        globalV.explore_csv_btn = i['explore_csv_btn']
        globalV.label_csv_selected = i['label_csv_selected']
        globalV.label_choose_csv = i['label_choose_csv']
        globalV.csv_missing = i['csv_missing']
        globalV.csv_missing_title = i['csv_missing_title']
        globalV.csv_error_Destinations_log = i['csv_error_Destinations_log']
        globalV.csv_error_Sites_log = i['csv_error_Sites_log']
        globalV.csv_error_InternalDomains_log = i['csv_error_InternalDomains_log']
        globalV.csv_error_InternalNetworks_log = i['csv_error_InternalNetworks_log']
        globalV.wrong_csv_line = i['wrong_csv_line']
        globalV.wrong_csv = i['wrong_csv']
        globalV.wrong_csv_title = i['wrong_csv_title']
        globalV.csv_already_registred = i['csv_already_registred']
        globalV.csv_already_registred_title = i['csv_already_registred_title']
        globalV.invalid_ip_log2 = i['invalid_ip_log2']
        globalV.invalid_ip_log1 = i['invalid_ip_log1']
        globalV.invalid_ip_message = i['invalid_ip_message']
        globalV.invalid_ip__message_title = i['invalid_ip__message_title']
        globalV.choose_valid_site = i['choose_valid_site']
        globalV.choose_valid_site_title = i['choose_valid_site_title']
        globalV.confirmation_site_assign = i['confirmation_site_assign']
        globalV.confirmation_title = i['confirmation_title']
        globalV.choose_valid_list = i['choose_valid_list']
        globalV.choose_valid_list_title = i['choose_valid_list_title']
        globalV.confirmation_list_assign = i['confirmation_list_assign']
        globalV.destinationName_text_empty = i['destinationName_text_empty']
        globalV.destinationName_text_empty_title = i['destinationName_text_empty_title']
        globalV.destinationManual_destination_label = i['destinationManual_destination_label']
        globalV.destinationManual_title_label = i['destinationManual_title_label']
        globalV.destinationManual_title = i['destinationManual_title']
        globalV.destinationManual_successfully_regitred = i['destinationManual_successfully_regitred']
        globalV.success_title = i['success_title']
        globalV.destinationManual_already_registred = i['destinationManual_already_registred']
        globalV.destinationManual_destination_text = i['destinationManual_destination_text']
        globalV.destinationManual_already_registred_title = i['destinationManual_already_registred_title']
        globalV.destination_list_assign_label = i['destination_list_assign_label']
        globalV.destinationCSV_title_label = i['destinationCSV_title_label']
        globalV.destinationCSV_title = i['destinationCSV_title']
        globalV.destination_log = i['destination_log']
        globalV.destination_successfully_registred = i['destination_successfully_registred']
        globalV.destination_successfully_registred_title = i['destination_successfully_registred_title']
        globalV.internalnetworks_site_assign_label = i['internalnetworks_site_assign_label']
        globalV.internalnetworks_title_label = i['internalnetworks_title_label']
        globalV.internalnetworks_title = i['internalnetworks_title']
        globalV.internalnetworks_log = i['internalnetworks_log']
        globalV.internalnetworks_timereg = i['internalnetworks_timereg']
        globalV.internalnetworks_successfully_registred = i['internalnetworks_successfully_registred']
        globalV.internalnetworks_successfully_registred_title = i['internalnetworks_successfully_registred_title']
        globalV.domainName_text_empty = i['domainName_text_empty']
        globalV.domainName_text_empty_title = i['domainName_text_empty_title']
        globalV.internaldomain_title_label = i['internaldomain_title_label']
        globalV.internaldomain_title = i['internaldomain_title']
        globalV.invalid_orgID_title = i['invalid_orgID_title']
        globalV.invalid_orgID_verify_email = i['invalid_orgID_verify_email']
        globalV.invalid_orgID_default = i['invalid_orgID_default']
        globalV.invalid_mgmt_title_verify_email = i['invalid_mgmt_title_verify_email'] 
        globalV.invalid_mgmt_verify_email = i['invalid_mgmt_verify_email']
        globalV.invalid_mgmt_default = i['invalid_mgmt_default']
        globalV.empty_email_text = i['empty_email_text']
        globalV.menu_exit = i['menu_exit']
        globalV.menu_configFile_title = i['menu_configFile_title'] 
        globalV.menu_configFile = i['menu_configFile']
        globalV.menu_policy_components = i['menu_policy_components']
        globalV.menu_destinations_csv = i['menu_destinations_csv']
        globalV.menu_destinations_manual = i['menu_destinations_manual']
        globalV.menu_domain = i['menu_domain']
        globalV.menu_domain_csv = i['menu_domain_csv']
        globalV.menu_domain_manual = i['menu_domain_manual']
        globalV.menu_internalNetworks = i['menu_internalNetworks']
        globalV.menu_internalNetworks_csv = i['menu_internalNetworks_csv']
        globalV.menu_sites = i['menu_sites']
        globalV.menu_sites_csv = i['menu_sites_csv']
        globalV.menu_sites_manual = i['menu_sites_manual']
        globalV.sites_successfully_registred_title = i['sites_successfully_registred_title']
        globalV.sites_successfully_registred = i['sites_successfully_registred']
        globalV.sites_log = i['sites_log']
        globalV.sitesCSV_title = i['sitesCSV_title']
        globalV.sitesCSV_title_label = i['sitesCSV_title_label']
        globalV.siteManual_already_registred_title = i['siteManual_already_registred_title']
        globalV.siteManual_already_registred = i['siteManual_already_registred']
        globalV.siteManual_succesfully_registred = i['siteManual_succesfully_registred']
        globalV.siteManual_siteName_label = i['siteManual_siteName_label']
        globalV.siteManual_title = i['siteManual_title']
        globalV.siteManual_title_label = i['siteManual_title_label']
        globalV.siteName_text_empty_title = i['siteName_text_empty_title']
        globalV.siteName_text_empty = i['siteName_text_empty']
        globalV.internaldomain_successfully_registred_title = i['internaldomain_successfully_registred_title'] 
        globalV.internaldomain_successfully_registred = i['internaldomain_successfully_registred']
        globalV.internaldomain_log = i['internaldomain_log']
        globalV.internaldomainCSV_title = i['internaldomainCSV_title']
        globalV.internaldomainCSV_title_label = i['internaldomainCSV_title_label'] 
        globalV.internaldomain_already_registred_title = i['internaldomain_already_registred_title']
        globalV.internaldomain_already_registred = i['internaldomain_already_registred']
        globalV.internaldomain_succesfully_registred = i['internaldomain_succesfully_registred']
        globalV.internaldomain_Name_label = i['internaldomain_Name_label']
        globalV.internaldomain_too_long_title = i['internaldomain_too_long_title']
        globalV.internaldomain_too_long = i['internaldomain_too_long']
        globalV.investigate_title = i['investigate_title']
        globalV.investigate_check_label = i ['investigate_check_label']
        globalV.investigate_typeURL_label = i['investigate_typeURL_label']
        globalV.investigate_clearBtn = i['investigate_clearBtn']
        globalV.investigate_addBtn = i['investigate_addBtn']
        globalV.investigate_checkBtn = i['investigate_checkBtn']
        globalV.investigate_addblacklistwindow_label = i['investigate_addblacklistwindow_label']
        globalV.investigate_message_notCategorized = i['investigate_message_notCategorized']
        globalV.investigate_message_status_clean = i['investigate_message_status_clean']
        globalV.investigate_message_status_malicious = i['investigate_message_status_malicious']
        globalV.investigate_message_status_notClassified = i['investigate_message_status_notClassified']
        globalV.investigate_labeldomain = i['investigate_labeldomain']
        globalV.investigate_labelstatus = i['investigate_labelstatus']
        globalV.investigate_labelcategorycontent = i['investigate_labelcategorycontent']
        globalV.investigate_labelcategorysec = i['investigate_labelcategorysec']
        globalV.investigate_invalidtoken = i['investigate_invalidtoken']
        globalV.investigate_notallowed = i['investigate_notallowed']
        globalV.investigate_domainName_text_empty = i['investigate_domainName_text_empty']
        globalV.investigate_menu_title = i['investigate_menu_title']
        globalV.reporting_menu_title = i['reporting_menu_title']
        globalV.reporting_title = i['reporting_title'] 
        globalV.reporting_title_label = i['reporting_title_label']
        globalV.reporting_btn_from = i['reporting_btn_from']
        globalV.reporting_btn_to = i['reporting_btn_to']
        globalV.reporting_btn_generateReport = i['reporting_btn_generateReport']
        globalV.reporting_btn_pickDate = i['reporting_btn_pickDate']
        globalV.reporting_success_message = i['reporting_success_message']
        globalV.reporting_empty_result = i['reporting_empty_result']
        globalV.invalid_reporting_default = i['invalid_reporting_default']
        globalV.reporting_empty_FromDate = i['reporting_empty_FromDate']
        globalV.reporting_empty_toDate = i['reporting_empty_ToDate']
        globalV.reporting_empy_date_title = i['reporting_empy_date_title']
        globalV.reporting_date_invalid = i['reporting_date_invalid']
        globalV.reporting_date_invalid_title = i['reporting_date_invalid_title']
        
         

############################# Root Window com as informações de acesso e primeiras configurações padrões #############################
root = Tk()
SetLang(language, True)
root.title(globalV.title_root + " ({})".format(versao)) 
root.wm_iconbitmap(iconImageFile)
root.minsize(400,100)
center(root)
root.resizable(0,0)
root.configure(background='#F0FFFF')
FirstTimeScript()


label = Label(root,text=globalV.title_label_root,font='Calibri 14 bold', bg='#F0FFFF')
label.grid(column=1,row=0,pady=6)

label = Label(root,text='Admin email: ', font='Calibri 10 bold', bg='#F0FFFF')
label.grid(column=0,row=1,padx=8, sticky='W') 

emailTxt = Text(root, width=25, height=1)
emailTxt.grid(column=1,row=1,padx=8,pady=2)
emailTxt.focus_set()


accessoBtn = HoverButton(root,text=globalV.access_btn_root,  width=28, activebackground='#0688fa', bg='#2dabf9', command = lambda: VerificaEmail(emailTxt.get("1.0","end-1c")))
accessoBtn.grid(column= 1, row = 4,pady=3)


label = Label(root,text=globalV.texto_label_linguagem_root, font='Calibri 10 bold', bg='#F0FFFF')
label.grid(column=0,row=5,padx=8, sticky='W') 

cmb_language = ttk.Combobox(root,state="readonly", width = 20, values=["Português", "English"])
cmb_language.place(relx=.28,rely=.5)
if language == "Portugues":
    cmb_language.current(0) 
elif language == "English":
    cmb_language.current(1)
    
#bindar para remover toda vez que fica selecionado, faz com que a janela fique com o foco
cmb_language.bind("<<ComboboxSelected>>",lambda e: SetLang(cmb_language.get(), False))



imghelp = ImageTk.PhotoImage(Image.open(InfoImageFile))
labelHelp = Label(root,image = imghelp, cursor="hand2", bg='#F0FFFF')
labelHelp.place(relx=.91, rely=.8)

labelcopyright = Label(root,text="© Valentim Uliana. All rights reserved", bg='#F0FFFF')
labelcopyright.place(relx=.0, rely=.9)

urlInfo = 'https://github.com/ValentimMuniz/Cisco-Umbrella-API-Calls'
labelHelp.bind('<Button-1>', lambda event : AbreURL(urlInfo))

root.bind('<KeyPress>', enterPressed)
############################# Fim da root Window #############################

############################# Estilizar progress bar e combobox #############################
# tem que colocar aqui porque aplica a todos combos e progress
s = ttk.Style()
s.theme_use('clam')

TROUGH_COLOR = 'black'
BG_COLOR = '#F0FFFF'
BAR_COLOR = 'green'
s.configure("bar.Horizontal.TProgressbar", troughcolor=BG_COLOR, bordercolor=TROUGH_COLOR, background=BAR_COLOR, lightcolor=BAR_COLOR, darkcolor=BAR_COLOR)
############################# Estilizar progress bar e combobox #############################


#Variáveis que precisam ser iniciadas pra funcionar o CSV import
internaldomainCSV = ""
SitesCSV = ""
internalNetCSV = ""
DestinationCSV = ""
error = ""

try:
    root.mainloop()
except (KeyboardInterrupt, SystemExit):
    sys.stdout.flush()
    pass