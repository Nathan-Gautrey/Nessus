#This file is Copyright Nathan Gautrey, licensed under the GPL2 license.

#Install python 3.5.2 and add python to path variable
#C:\Users\<user>\AppData\Local\Programs\Python\Python35-32\Scripts> .\easy_install xlsxwriter


import csv
#import pprint
import xlsxwriter

#Open csv file

reader = csv.DictReader(open('test_scan_900z53.csv', 'r'))
dict_list = []

#Loop through csv file and create a new dict for each row
#Place all dicts in a list (dict_list)

for line in reader:
    dict_list.append(line)

#Close file after reading


#Create unique sets for each attribute
Pluginid_set = set()
cve_set = set()
cvss_set = set()
risk_set = set()
host_set = set()
port_set = set()
plugin_name_set = set()

#Loop through list of dicts and add values from each dict
#Plugin ID used for key in dictionarys

for line in dict_list:    
    Pluginid_set.add((line["Plugin ID"], line["Synopsis"]))
    plugin_name_set.add((line["Plugin ID"], line["Name"]))
    cve_set.add((line["Plugin ID"], line["CVE"]))
    cvss_set.add(line["CVSS"])
    risk_set.add(line["Risk"])
    host_set.add(line["Host"])
    port_set.add(line["Port"])

#Turn Plugins into dictionary so lookups can be carried out
pluginid_dict = dict(Pluginid_set)
plugin_name_dict = dict(plugin_name_set)
cve_dict = dict(cve_set)

#xlsx output  
workbook = xlsxwriter.Workbook('nessus-csv-output.xlsx')
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


#Output each detected vulnerability with the corrisponding host and service

with open('nessus-csv-output.csv', 'w') as csvfile:
    nessuswriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
    fieldnames = ['Risk', 'Plugin ID', 'Service', 'Detected Vulnerability']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()


    #Loop through by risk so output is in risk order.
    for risk in risk_set:

        #Loop by plugin and then extra each matching host and service
        for plugin in pluginid_dict:
            
            local_services = str()      #Store services running per plugin
            for host in host_set:
                host_service = []       #Store services running per host per plugin

                #From the csv match the risk, plugin and host then store the Host and port.
                
                for line in dict_list:
                    if risk == line['Risk'] and plugin == line['Plugin ID'] and host == line["Host"]:
                        host_service.append({'Host' : host, 'Port' : line['Port']})

                #Loop through each host_ip and port and convert from dict into string

                for idx,row in enumerate(host_service):
                    temp=""
                    temp=str.format(row['Host']),":",str.format(row['Port'])
                    temp = ''.join(temp)

                   #Add a newline if it is not the last in the host_service list

                    if idx != (len(host_service)-1):
                        local_services = local_services,''.join(temp),"\n"
                    else:
                        #Catch corner case of single service on multiple hosts, newline require for new host
                        if local_services and (0 == idx) :
                            local_services = local_services + "\n"
                        local_services = local_services,''.join(temp)
                    #Change the output into a string removing all brackets
                    local_services = ''.join(local_services)

            #Create a CVE field and fill in the plugin has an assosiated CVE, if not show N/A            
            cve_detected = ""
            cve_detected = str.format(cve_dict[plugin])
            if "" == cve_detected : cve_detected = "N/A"

            #Create a field called Detected Vulnerability which combines Plugin Name & Synopsys on a seperate line
            detected_vulnerability = str.format(plugin_name_dict[plugin]) + "\n" + cve_detected + "\n" + str.format(pluginid_dict[plugin])


            #If vulnerable services are found create a dictionary of the information and write to csv
            if local_services:
                vuln={'Risk':risk, 'Plugin ID': plugin, 'Service' : local_services, 'Detected Vulnerability' : detected_vulnerability}
                writer.writerow(vuln) # write csv file

                #xlsx Output
                worksheet.write_rich_string(index_row, 0, risk)
                worksheet.write_rich_string(index_row, 1, plugin)
                worksheet.write_rich_string(index_row, 2, local_services, format)
                worksheet.write_rich_string(index_row, 3, bold, str.format(plugin_name_dict[plugin]) + "\n", blue, cve_detected + "\n", gray, str.format(pluginid_dict[plugin]), format)
                index_row += 1 # incremember xlsx file row by 1

       
    # Close csv file after use  
    csvfile.close()
# Close xlsx file after use
workbook.close()


### DEBUG CODE
    
#Open csv file

#reader = csv.DictReader(open('nessus-csvf-output.csv', 'rb'))
#output_dict_list = []

#Loop through csv file and create a new dict for each row
#Place all dicts in a list (dict_list)

#for line in reader:
#    output_dict_list.append(line)


#Print Output

#pp = pprint.PrettyPrinter()

#for i in output_dict_list:
#   print (pp.pprint(i))
  

