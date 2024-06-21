import requests
import json


#Functions for cleansing data
def partial_data(group_dict, attack_dict):
     #Removing columns 
     for group in group_dict:
          group_dict[group].pop('modified')
          if 'x_mitre_deprecated' in group_dict[group]:
               group_dict[group].pop('x_mitre_deprecated')
          group_dict[group].pop('x_mitre_version')
          if 'x_mitre_contributors' in group_dict[group]:
               group_dict[group].pop('x_mitre_contributors')
          if 'created_by_ref' in group_dict[group]:
               group_dict[group].pop('created_by_ref')
          if 'revoked' in group_dict[group]:
               group_dict[group].pop('revoked')
          group_dict[group].pop('external_references')
          if 'object_marking_refs' in group_dict[group]:
               group_dict[group].pop('object_marking_refs')
          group_dict[group].pop('x_mitre_domains')
          if 'x_mitre_attack_spec_version' in group_dict[group]:
               group_dict[group].pop('x_mitre_attack_spec_version')
          if 'x_mitre_modified_by_ref' in group_dict[group]:
               group_dict[group].pop('x_mitre_modified_by_ref')
          ##########
          if 'modified' in group_dict[group]:
               group_dict[group].pop('description')
          group_dict[group].pop('created')
          if 'modified' in group_dict[group]:
               group_dict[group].pop('modified')
     # if 'aliases' in group_dict[group]:
          # group_dict[group].pop('aliases')
          
     for attack in attack_dict:
          #print(attack_dict[attack])
          if 'x_mitre_deprecated' in attack_dict[attack]:
               attack_dict[attack].pop('x_mitre_deprecated')
          if 'x_mitre_version' in attack_dict[attack]:
               attack_dict[attack].pop('x_mitre_version')
          if 'x_mitre_contributors' in attack_dict[attack]:
               attack_dict[attack].pop('x_mitre_contributors')
          #if 'revoked' in attack_dict[attack]:
          #    attack_dict[attack].pop('revoked')
          if 'x_mitre_attack_spec_version' in attack_dict[attack]:
               attack_dict[attack].pop('x_mitre_attack_spec_version')
          if 'x_mitre_data_sources' in attack_dict[attack]:
               attack_dict[attack].pop('x_mitre_data_sources')
          attack_dict[attack].pop('created_by_ref')
          attack_dict[attack].pop('x_mitre_modified_by_ref')
          attack_dict[attack].pop('object_marking_refs')
          attack_dict[attack].pop('x_mitre_domains')
          attack_dict[attack].pop('modified')
          ########################3
          attack_dict[attack].pop('description')
          if 'x_mitre_defense_bypassed' in attack_dict[attack]:
               attack_dict[attack].pop('x_mitre_defense_bypassed')
          attack_dict[attack].pop('created')
          if 'x_mitre_detection' in attack_dict[attack]:
               attack_dict[attack].pop('x_mitre_detection')


def full_data(group_dict, attack_dict):
     for group in group_dict:
          group_dict[group].pop('modified')
          if 'x_mitre_deprecated' in group_dict[group]:
               group_dict[group].pop('x_mitre_deprecated')
          group_dict[group].pop('x_mitre_version')
          if 'x_mitre_contributors' in group_dict[group]:
               group_dict[group].pop('x_mitre_contributors')
          if 'created_by_ref' in group_dict[group]:
               group_dict[group].pop('created_by_ref')
          if 'revoked' in group_dict[group]:
               group_dict[group].pop('revoked')
          group_dict[group].pop('external_references')
          if 'object_marking_refs' in group_dict[group]:
               group_dict[group].pop('object_marking_refs')
          group_dict[group].pop('x_mitre_domains')
          if 'x_mitre_attack_spec_version' in group_dict[group]:
               group_dict[group].pop('x_mitre_attack_spec_version')
          if 'x_mitre_modified_by_ref' in group_dict[group]:
               group_dict[group].pop('x_mitre_modified_by_ref')
          if 'techniques' not in group_dict[group]:
               group_dict[group]['techniques'] = []

          
     for attack in attack_dict:
          if 'x_mitre_deprecated' in attack_dict[attack]:
               attack_dict[attack].pop('x_mitre_deprecated')
          if 'x_mitre_version' in attack_dict[attack]:
               attack_dict[attack].pop('x_mitre_version')
          if 'x_mitre_contributors' in attack_dict[attack]:
               attack_dict[attack].pop('x_mitre_contributors')
          if 'revoked' in attack_dict[attack]:
               attack_dict[attack].pop('revoked')
          if 'x_mitre_attack_spec_version' in attack_dict[attack]:
               attack_dict[attack].pop('x_mitre_attack_spec_version')
          if 'x_mitre_data_sources' in attack_dict[attack]:
               attack_dict[attack].pop('x_mitre_data_sources')
          attack_dict[attack].pop('created_by_ref')
          attack_dict[attack].pop('x_mitre_modified_by_ref')
          attack_dict[attack].pop('object_marking_refs')
          attack_dict[attack].pop('x_mitre_domains')
          attack_dict[attack]['tools'] =[]
          attack_dict[attack]['mitigations'] =[]
         
          



def createFilesFromGithub():
     response = requests.get('https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v14.1/enterprise-attack/enterprise-attack.json').json()

     group_dict = {}
     attack_dict = {}
     relationship_dict ={}
     tool_dict ={}
     mitigation_dict = {}

     for item in response['objects']:
          if 'type' in item:
               # Getting all attack objects
               if item['type'] == 'attack-pattern':
                    attack_dict[item['id']] = item
               # Getting all relationship objects
               elif item['type'] == 'relationship':
                    relationship_dict[item['id']] = item
               # Getting all actor objects
               elif item['type'] == 'intrusion-set':
                    group_dict[item['id']] = item
               elif item['type'] == 'tool':
                    tool_dict[item['id']] = item
               elif item['type'] == 'course-of-action':
                    mitigation_dict[item['id']] = item

     new_attack_dict = []
     new_tool_dict = []
     new_mitigation_dict =[]
     #Partial data --------------------------------------------------------------->Partial
     #partial_data(group_dict.copy(),attack_dict.copy())
     #Full data --------------------------------------------------------------->Full
     full_data(group_dict.copy(),attack_dict.copy())

     for relationship in relationship_dict:

          #If the source ref of the relationship is an attack group
          if relationship_dict[relationship]['source_ref'] in group_dict :
               group = group_dict[relationship_dict[relationship]['source_ref']]
               #Try and catch because relatinohsips are also exist between tools and groups
               try:
                    attack = attack_dict[relationship_dict[relationship]['target_ref']]
               except:
                    continue

               # Find technique of the subtechnique
               # If the attack is a subtechnique, else add it the dictionary anyways
               if attack['x_mitre_is_subtechnique'] == True:
                    # Loop through dictionary in order to find the techniques parent
                    for relationship_sep in relationship_dict:
                         # If the relationship is source reference is of the attack we found and the relationship type of this technique is subtechnique
                         if relationship_dict[relationship_sep]['source_ref'] == attack['id'] and relationship_dict[relationship_sep]['relationship_type']  == 'subtechnique-of':
                              sub_technique = attack_dict[relationship_dict[relationship_sep]['target_ref']]['name']
                              main_tactics = attack_dict[relationship_dict[relationship_sep]['target_ref']]['kill_chain_phases']
                              attack['sub_technique_of'] = sub_technique
                              attack['main_tactics_of'] =[]
                              # This technique is also shared in multiple other tactics, so i set into an array
                              for  tatic in main_tactics:
                                   attack['main_tactics_of'].append(tatic['phase_name'])
                         
                              if 'attack_id' not in attack:
                                        attack['attack_id'] = attack['external_references'][0]['external_id']
                                        attack.pop("external_references")
                                        new_attack_dict.append(attack)

                              # Add the technique to the techniques array element of the attack group
                              group_dict[group['id']]['techniques'].append(attack['id'])
                         
                              #print(group_dict[group['id']])
               else:
                    if 'attack_id' not in attack:
                         attack['attack_id'] = attack['external_references'][0]['external_id']
                         attack.pop("external_references")
                         new_attack_dict.append(attack)
                    group_dict[group['id']]['techniques'].append(attack['id']) 
          elif relationship_dict[relationship]['source_ref'] in tool_dict and relationship_dict[relationship]['target_ref'] in attack_dict:
               if 'tools' not in attack_dict[relationship_dict[relationship]['target_ref']]:
                    attack_dict[relationship_dict[relationship]['target_ref']]['tools'] =[]
               attack_dict[relationship_dict[relationship]['target_ref']]['tools'].append(tool_dict[relationship_dict[relationship]['source_ref']]['id'])
               if tool_dict[relationship_dict[relationship]['source_ref']] not in new_tool_dict:
                    new_tool_dict.append(tool_dict[relationship_dict[relationship]['source_ref']])
          elif relationship_dict[relationship]['source_ref'] in mitigation_dict and relationship_dict[relationship]['target_ref'] in attack_dict:
               if 'mitigations' not in attack_dict[relationship_dict[relationship]['target_ref']]:
                    attack_dict[relationship_dict[relationship]['target_ref']]['mitigations'] =[]
               attack_dict[relationship_dict[relationship]['target_ref']]['mitigations'].append(mitigation_dict[relationship_dict[relationship]['source_ref']]['id'])
               if mitigation_dict[relationship_dict[relationship]['source_ref']] not in new_tool_dict:
                    new_mitigation_dict.append(mitigation_dict[relationship_dict[relationship]['source_ref']])
          

     # Write to JSON file 
     json_str = json.dumps(list(group_dict.values()), indent=4)  

     # Define your JSON file name
     json_file_path = './intrusion_sets.json'

     # Write JSON string to a file
     with open(json_file_path, 'w') as json_file:
          json_file.write(json_str)

     print(f"Dictionarysaved to {json_file_path}")
     print( len(group_dict['intrusion-set--01e28736-2ffc-455b-9880-ed4d1407ae07']['techniques']))
     print( len(group_dict['intrusion-set--6713ab67-e25b-49cc-808d-2b36d4fbc35c']['techniques']))

     json_file_path = './techniques.json'

     json_str = json.dumps(list(new_attack_dict), indent=4)  

     # Write JSON string to a file
     with open(json_file_path, 'w') as json_file:
          json_file.write(json_str)

     print(f"Dictionarysaved to {json_file_path}")
     print( len(group_dict['intrusion-set--01e28736-2ffc-455b-9880-ed4d1407ae07']['techniques']))
     print( len(group_dict['intrusion-set--6713ab67-e25b-49cc-808d-2b36d4fbc35c']['techniques']))

     json_file_path = './tool_sets.json'

     json_str = json.dumps(list(new_tool_dict), indent=4)  

     # Write JSON string to a file
     with open(json_file_path, 'w') as json_file:
          json_file.write(json_str)

     print(f"Dictionarysaved to {json_file_path}")

     json_file_path = './mitigations.json'

     json_str = json.dumps(list(new_mitigation_dict), indent=4)  
     # Write JSON string to a file
     with open(json_file_path, 'w') as json_file:
          json_file.write(json_str)

     print(f"Dictionarysaved to {json_file_path}")
     print( len(group_dict['intrusion-set--01e28736-2ffc-455b-9880-ed4d1407ae07']['techniques']))
     print( len(group_dict['intrusion-set--6713ab67-e25b-49cc-808d-2b36d4fbc35c']['techniques']))


