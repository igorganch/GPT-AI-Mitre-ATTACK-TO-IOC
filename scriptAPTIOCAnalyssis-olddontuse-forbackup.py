import json


class iocobj:
    def __init__(self, name):
        self.indicator = name
        self.attack_ids = []
        self.industries = []
        self.targeted_countries=[]

    # Method to convert the object to a dictionary
    def to_dict(self):
        return {
            "indicator": self.indicator,
            "attack_ids": self.attack_ids,
            "industries": self.industries,
            "targeted_countries": self.targeted_countries
        }
    
    def set_attack_ids(self,attack):
        if attack not in self.attack_ids:
            self.attack_ids.append(attack)
        
    def set_industries(self,industry):
        if industry not in self.industries:
            self.industries.append(industry)
   
    def set_targeted_countries(self,target):
        if target not in self.targeted_countries:
            self.targeted_countries.append(target)

class group_possiblity:
    def __init__(self, name, id):
        self.name = name
        self.possibility = 0 
        self.attack_ids = []
        self.targeted_industries = []
        self.targeted_countries = []
        self.id = id
    def add_matching_attackid(self,attack_id):
        self.attack_ids.append(attack_id)
    def add_matching_industry(self,industry):
        self.targeted_industries.append(industry)
    def add_matching_country(self,country):
        self.targeted_countries.append(country)
    def get_attack_ids_len(self):
        return  len(self.attack_ids)
    def get_targeted_industries_len(self):
        return  len(self.targeted_industries)
    def get_all_matching(self):
        return (len(self.attack_ids) + len(self.targeted_industries) + len(self.targeted_countries))
    def to_dict(self):
        return {
            "name": self.name,
            "id": self.id,
            "attack_ids": self.attack_ids,
            "possibility": self.possibility,
            "targeted_industries": self.targeted_industries,
            "targeted_countries": self.targeted_countries,
            "count": (len(self.attack_ids) + len(self.targeted_industries) + len(self.targeted_countries))
        }
    
    def set_possiblity(self, length_ioc, length_industry, length_countries ):
        self.possibility = (len(self.attack_ids) + len(self.targeted_industries) + len(self.targeted_countries))  /  (length_ioc + length_industry + length_countries)

def scriptAPTIOCAnalysisFunc(): 
    # Assuming your JSON file is named 'data.json'
    with open('IOC-data.json', 'r') as file:
        iocs = json.load(file)
        iocs = iocs['IPSignatures']

    with open('output1.json', 'r') as file:
        groups = json.load(file)

    with open('output2.json', 'r') as file:
        groups2 = json.load(file)

    ioc_dict = []

    for ioc in iocs:
    #   print(ioc['indicator'])
        iocobj_obj = iocobj(ioc['indicator'])
        for pulse in ioc['pulse_info']['pulses']:
            #print(len(pulse['attack_ids']))
            if len(pulse['attack_ids']) != 0:
        #       print("-------------attack_ids ----------")
                for attack in pulse['attack_ids']:
                    #print(attack)
                    iocobj_obj.set_attack_ids(attack)
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
        ioc_dict.append(iocobj_obj.to_dict())
    #  print('-------------------------------------------------------------------')
    
    for groupstemp in groups:
        for groupstemp2 in groups2:
            if groupstemp["id"] == groupstemp2["id"]:
                groupstemp['targeted_countries'] = groupstemp2['targeted_countries']
                break
        

    for ioc in ioc_dict:
        ioc['possiblities_in_percentage'] = []
        length_attack_ids = len(ioc['attack_ids'])
        length_industries = len(ioc['industries'])
        length_countries = len( ioc['targeted_countries'])
        ioc['total_count'] = length_industries + length_countries + length_attack_ids
        for group in groups:
            print(group["id"])
            group_possible = group_possiblity(group["name"],group["id"] )
            for tecnhique in group['techniques']:
                for attack_id in ioc['attack_ids']:
                    if attack_id['id'] == tecnhique['attack_id']:
                        group_possible.add_matching_attackid(attack_id)
                       
                        break
            for target_industry in group['targeted_industries']:
                print("target_industry - " + target_industry)    
                for industry in ioc['industries']:
                    print("industry - " +industry)
                    print("target_industry - " +target_industry)
                    if industry == target_industry:
                        print("fuckkkks")
                        group_possible.add_matching_industry(industry)
                        break
            for target_country in group['targeted_countries']:
                print("target_country - " + target_country)    
                for country in ioc['targeted_countries']:
                    print("industry - " +country)
                    print("target_country - " +target_country)
                    if country == target_country:
                        print("fuckkkks")
                        group_possible.add_matching_country(country)
                        break
            if group_possible.get_attack_ids_len()  > 0 or  group_possible.get_targeted_industries_len() > 0:
                group_possible.set_possiblity(length_attack_ids, length_industries,length_countries)
                ioc['possiblities_in_percentage'].append(group_possible.to_dict())


    filename = 'IOC-data-Analysis.json'

    #Writing the JSON data to the file
    with open(filename, 'w') as file:
        json.dump(ioc_dict, file, indent=4)
    #Run the scriptTTPAnalysis.py and return the created file.
