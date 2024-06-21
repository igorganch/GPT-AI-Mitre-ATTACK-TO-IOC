import json

# Assuming your JSON file is named 'data.json'
def convert_to_jsonl(json_file, jsonl_file):
    with open(json_file, 'r') as infile, open(jsonl_file, 'w') as outfile:
        data = json.load(infile)
        for item in data:
            json.dump(item, outfile)
            outfile.write('\n')

def scriptTTPAnalysisFunc():
    with open('intrusion_sets.json', 'r') as file:
        groups = json.load(file)

    with open('techniques.json', 'r') as file:
        techniques = json.load(file)

    with open('tool_sets.json', 'r') as file:
        tools = json.load(file)

    with open('mitigations.json', 'r') as file:
        mitigations = json.load(file)


    for group in groups:
        group["targeted_industries"] =[]
        group["targeted_countries"]=[]
        print("Group - " + group["name"])
        i = 0
        #Iterate each tecnhique id 
        temp_techniques =  group["techniques"].copy()
        group["techniques"] =[]
        for technique_id in temp_techniques:
            
            #Iterate through techniques to find technique id that matches
            for technique in techniques:
                #find technique id that matches that matches
                if technique['id'] == technique_id:
                
                    temp_tools =  technique["tools"].copy()
                    technique["tools"] =[]
                    for tool_id in temp_tools:
                        
                        #Iterate through tools to find tool id that matches tool_id
                        for tool in tools:
                            if tool_id == tool["id"]:  
                                print("found Tool - " + str(i) + " - " + tool['name'] + " " +  tool['id'])
                                technique["tools"].append(tool)
                                break
                    
                    temp_mitigations =  technique["mitigations"].copy()
                    technique["mitigations"] =[]
                    for mitigation_id in temp_mitigations:
                        #Iterate through tools to find tool id that matches tool_id
                        for mitgation in mitigations:
                            if mitigation_id == mitgation["id"]:  
                                technique["mitigations"].append(tool)
                                break
                    temp = technique.copy()
                    group["techniques"].append(temp)

        
  

    filename = 'APT-TTP-Analysis.jsonl'
    
    #Writing the JSON data to the file
    with open('temp.json', 'w') as file:
        json.dump(groups, file, indent=4)
        
    convert_to_jsonl('temp.json', filename)

    print(f"Data successfully written to {filename}")
    for group in groups: 
        for technique in group['techniques']:
            technique.pop('tools')
            technique.pop('mitigations')
    
    filename = 'APT-temp.json'

    #Writing the JSON data to the file
    with open(filename, 'w') as file:
        json.dump(groups, file, indent=4)
    

    print(f"Data successfully written to {filename}")
    

#scriptTTPAnalysisFunc()
    #Don't do anything else but run the scriptTTPnalysis.py and return the created file.
    #Dont do anything else but edit the APT.json file and fill in the fields empty fields "industry" and "country" only using the description of the object and send back the edited file