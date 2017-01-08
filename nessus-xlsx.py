#This file is Copyright Nathan Gautrey, licensed under the GPL2 license.

#Install python 3.5.2 and add python to path variable
#C:\Users\<user>\AppData\Local\Programs\Python\Python35-32\Scripts> .\easy_install xlsxwriter

#To Do
#pep8 looks at the code readability


#Imports
import csv
import xlsxwriter
## cli arguments and options
import argparse
import os.path

############################# Menu ############################

#Check file extension is a .csv
#return filename e.g. nessus.csv

def valid_input_file(s):
    if not s.endswith('.csv'):
        raise argparse.ArgumentTypeError("Not a valid file extension")
    return(os.path.basename(s))

#Create the parser and set the type to the function

parser = argparse.ArgumentParser()
parser.add_argument("--inputfile", "-i", help="Input file .cvs", type=valid_input_file)
args = parser.parse_args()

#args variable holds the result of the inputfile name
#create an output filename from the input

outputfile = os.path.splitext(args.inputfile)[0] + ".xlsx"


############################# Objects #############################


class vulnerability:
    
    def __init__(self, pluginid, plugin_name, cve, cvss, risk, synopsis):
        self.pluginid = pluginid
        self.plugin_name = plugin_name
        self.cve = cve
        if self.cve == "":
            self.cve = "N/A"
        self.cvss = cvss
        self.risk = risk
        self.synopsis = synopsis
        self.service = []

    def addservice(self,host,service,protocol):
         self.service.append([host,service,protocol])

    def host_service(self):
        
        host_service = ""
        for idx,service in enumerate(self.service):
            host_service = host_service + service[0]+":"+service[1]
            if (len(detected_vulnerability.service)-1) != idx:
                host_service = host_service +"\n"
                
        return host_service   

############################# Read CSV #############################


#Open csv file
reader = csv.DictReader(open(args.inputfile, 'r'))
csv_dict_list = []

#Loop through csv file and create a new dict for each row
#Place all dicts in a list (csv_dict_list)

for line in reader:
    csv_dict_list.append(line)

############################# Create Sets #############################


#Loop through csv file and create a list of unique (set) of plugin IDs

##Create unique set of plugin IDs & Hosts
pluginid_set = set()

for line in csv_dict_list: 
    pluginid_set.add(line["Plugin ID"])

############################# Populate Objects #############################


#Create a list of objects (detected_vulnerabilities_list)
#Where each object (detected_vulnerability) is a single plugin ID
#Break once data is retrieved from non-unique dict list
    
detected_vulnerabilities_list = []

for id in pluginid_set:
    for line in csv_dict_list:
        if id == line["Plugin ID"]:
            detected_vulnerability = vulnerability(line["Plugin ID"],line["Name"],line["CVE"],line["CVSS"],line["Risk"],line["Synopsis"])
            detected_vulnerabilities_list.append(detected_vulnerability)
            break 

#Update detected_vulnerability object in detected_vulnerabilities_list for each vulnerable_services per plugin
        
for line in csv_dict_list:
    for id in detected_vulnerabilities_list:
        if id.pluginid == line["Plugin ID"]:
            id.addservice(line["Host"],line["Port"],line["Protocol"])
            

############################# XLSX Writer Format #############################


#xlsx output  
workbook = xlsxwriter.Workbook(outputfile)
worksheet = workbook.add_worksheet()
worksheet.set_column(2, 2, 30)  # Width of column B set to 30.
worksheet.set_column(3, 3, 120)  # Width of column B set to 30.

index_row = 2 # Starting Row for xlsx file

# Set up some formats to use.
format = workbook.add_format()  #Format as we go
format.set_text_wrap() # Wrap Long strings
bold = workbook.add_format({'bold': True})
italic = workbook.add_format({'italic': True})
gray = workbook.add_format({'color': 'gray'})
blue = workbook.add_format({'color': 'blue'})

#Set Headers
xlsx_header_row = ('Risk', 'Plugin ID', 'Service', 'Detected Vulnerability')
worksheet.write_row(1, 0, xlsx_header_row,bold)


############################# XLSX Writer Output #############################

#Open file to write to and name fields


# For each object (detected_vulnerability) in the list (detected_vulnerabilities_list)
# Write output to the Xlsx workbook

for detected_vulnerability in detected_vulnerabilities_list:
    worksheet.write_rich_string(index_row, 0, detected_vulnerability.risk)
    worksheet.write_rich_string(index_row, 1, detected_vulnerability.pluginid)
    worksheet.write_rich_string(index_row, 2, detected_vulnerability.host_service(), format)
    worksheet.write_rich_string(index_row, 3, bold, detected_vulnerability.plugin_name + "\n", blue, detected_vulnerability.cve + "\n", gray, detected_vulnerability.synopsis, format)
    index_row += 1 # incremember xlsx file row by 1

       
# Close xlsx file after use
workbook.close()


############################# Debug #############################
#from pprint import pprint
#for p in detected_vulnerabilities_list:
#    pprint (vars(p))
    
