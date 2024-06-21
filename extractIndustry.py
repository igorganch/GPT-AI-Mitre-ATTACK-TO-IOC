import json

class iocobj:
    def __init__(self):
        self.industries = []
        self.targeted_countries=[]

    # Method to convert the object to a dictionary
    def to_dict(self):
        return {
            "industries": self.industries,
            "targeted_countries": self.targeted_countries
        }
    
        
    def set_industries(self,industry):
        if industry not in self.industries:
            self.industries.append(industry)
   
    def set_targeted_countries(self,target):
        if target not in self.targeted_countries:
            self.targeted_countries.append(target)

def extractIndustry():
    with open('IOC-data.json', 'r') as file:
        iocs = json.load(file)
        iocs = iocs['IPSignatures']


    iocobj_obj = iocobj()
    for ioc in iocs:

        for pulse in ioc['pulse_info']['pulses']:
    
            if len(pulse['industries']) != 0:
        #        print("-------------industries ----------")
                for insdustry in pulse['industries']:
                    #print(insdustry)
                    iocobj_obj.set_industries(insdustry)
            if len(pulse['targeted_countries']) != 0:
                    for country in pulse['targeted_countries']:
                        #print(country)
                        iocobj_obj.set_targeted_countries(country)

    # print('---------------')
        if 'country_name' in ioc:
            iocobj_obj.set_targeted_countries(ioc['country_name'])
            print("true")

    filename = 'Industry-Countries.json'

    #Writing the JSON data to the file
    with open(filename, 'w') as file:
        json.dump(iocobj_obj.to_dict(), file, indent=4)