import json

# Assuming your JSON file is named 'data.json'
def convert_to_jsonl(json_file, jsonl_file):
    with open(json_file, 'r') as infile, open(jsonl_file, 'w') as outfile:
        data = json.load(infile)
        for item in data:
            json.dump(item, outfile)
            outfile.write('\n')
def scriptToolsAnalysisFunc():
    with open('intrusion_sets.json', 'r') as file:
        groups = json.load(file)

    with open('techniques.json', 'r') as file:
        techniques = json.load(file)

    with open('tool_sets.json', 'r') as file:
        tools = json.load(file)

    for group in groups:
        group["tools"] = []
        print("Group - " + group["name"])
        i = 0
        #Iterate each tecnhique id 
        for technique_id in group["techniques"]:
            #Iterate through techniques to find technique id that matches
            for technique in techniques:
                #find technique id that matches that matches
                if technique['id'] == technique_id:
                    print("found technique - " + str(i) + " - " + technique['name'])
                    #Iterate through each teachniques tool array
                    for tool_id in technique['tools']:
                        #Iterate through tools to find tool id that matches tool_id
                        for tool in tools:
                            if tool_id == tool["id"]:  
                                print("found tool - " + str(i) + " - " + tool['name'])
                                if tool not in group["tools"]:
                                    group["tools"].append(tool)
                                break
                    print(i)
                    i = i + 1


    filename = 'toolsAnlaysis.jsonl'
    for group in groups:
        print(group['name'] + " Length - " + str(len(group["tools"])))
    #Writing the JSON data to the file
    with open('temp.json', 'w') as file:
        json.dump(groups, file, indent=4)

    convert_to_jsonl('temp.json',filename)

    print(f"Data successfully written to {filename}")
    #Don't do anything else but run the scriptToolsAnalysis.py and return the created file.
scriptToolsAnalysisFunc()