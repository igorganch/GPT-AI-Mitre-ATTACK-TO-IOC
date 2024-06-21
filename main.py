from pathlib import Path
from openai import OpenAI

# optional; defaults to `os.environ['OPENAI_API_KEY']`
import os
import asyncio
import shutil
import json
import re 
from script import createFilesFromGithub
from scriptToolsAnalysis import scriptToolsAnalysisFunc
from scriptAPTIOCAnalyssis import scriptAPTIOCAnalysisFunc
from scriptTTPAnalysis import scriptTTPAnalysisFunc
from extractIndustry import extractIndustry
api_key_system = os.getenv("API_KEY")
asst_id = os.getenv("ASSISTANT_ID")


#Uploading files to GPT-4 Turbo
def uploadFile(file1, client):
  file = client.files.create(
    file=Path(file1),
    purpose="assistants",
  )
  client.beta.assistants.files.create(assistant_id=asst_id, file_id=file.id)
  return file 

def remove_last_comma(s):
    # Find the last comma in the string
    last_comma_pos = s.rfind(',')
    # If a comma is found, split the string and rejoin without the last comma
    if last_comma_pos != -1:
        return s[:last_comma_pos] + s[last_comma_pos + 1:]
    # Return the original string if no comma is found
    return s

# Example usage


  
#Creating a GPT-4 Turbo Assistant
def createAssistant(client):
  assistant = client.beta.assistants.create(
  name="Data visualizer",
  description="Send me back all APT's just names in json format",
  model="gpt-4-turbo-preview",
  tools=[{"type": "code_interpreter"}],
  file_ids=["file-fvC0CCSQ3yJzYvUPrXHuMyqb"]
  )
  return assistant


#The actual prompting 
async def promptAssistant(client,prompts):
  #Creating thread 
  #await asyncio.sleep(30)
  threads =[]
  #Run all prompts
  for prompt in prompts:
    thread =  client.beta.threads.create()
    #Creating Message  
   
    message =  client.beta.threads.messages.create(
      thread_id=thread.id,
      role="user",
      content=prompt
    )
    #Add message to thread
    run =  client.beta.threads.runs.create(
      thread_id=thread.id,
      assistant_id="asst_gmaH8hjQZu0UYVMcKvJ9GwGV",
      instructions="Complete the task the user requested."
    )
    thread.run = run
    threads.append(thread)

  complete = False 
  complete_thread =[]
  #Reason for this is so that we don't overload the API, More API calls = More money. A wait function is created to query the api if the task had been completed 
  while (complete == False):
  
    await asyncio.sleep(60)
    for thread in threads:
      run_status =  client.beta.threads.runs.retrieve(
      thread_id=thread.id,
      run_id=thread.run.id
      )

      if run_status.status == "completed":
        complete_thread.append(thread)
    print("Threads - " + str(len(threads)))
    print("complete_thread - " + str(len(complete_thread)))
    if len(threads) == len(complete_thread):
      complete = True
    

  messages = []

  for thread in complete_thread:
    message = client.beta.threads.messages.list(
      thread_id=thread.id
    )
    messages.append(message)
#Display message 
  return messages 



async def main():
    #Run all scripts to fetch data / clean data
    scriptToolsAnalysisFunc()
    scriptTTPAnalysisFunc()
    extractIndustry()

    client = OpenAI(
        # This is the default and can be omitted
        api_key=api_key_system,
    )
    apttemp = uploadFile('./APT-temp.json', client)
  
    #Load up cleaned data that will be used for prompt, inclusing each IOC info such as countries & inudstries that were reportedly targeted 
    with open('Industry-Countries.json', 'r') as file:
        data = json.load(file)

    #Building the prompt for GPT (PROMPT ENGINEERING)
    prompt = "Utilize the descriptions provided in the JSON file named '" + apttemp.id + "' to identify and update the 'targeted_countries' for each listed cyber threat group. Use the nuance phrases to figure out the targeted countries. The updates for 'targeted_countries' should strictly come from this provided list here " 
    for industry in data['targeted_countries']:
      prompt = prompt +   "'" +  industry + "', "
    prompt = remove_last_comma(prompt)
    prompt = prompt + ". If no country from the list is mentioned in the APT's description, update the 'targeted_countries' field to 'none'. Analyze each threat group's description to infer the correct industries. Maintain the original structure and format of the JSON structure and provide the updated file.  Do not send me any text just send back the edited file."
    
    prompt2 = "Utilize the descriptions provided in the JSON file named '" + apttemp.id + "' to identify and update the 'targeted_industries' for each listed cyber threat group. Use the nuance phrases to figure out the targeted industries. The updates for 'targeted_industries' should strictly come from this provided list here " 
    for industry in data['industries']:
      prompt2 = prompt2 +   "'" +  industry + "', "
    prompt2 = remove_last_comma(prompt2)
    prompt2 = prompt2 + ". If no industry from the list is mentioned in the APT's description, update the 'targeted_industries' field to 'none'. Analyze each threat group's description to infer the correct industries. Maintain the original structure and format of the JSON structure and provide the updated file.  Do not send me any text just send back the edited file."
    
    #Appending prompts to an array to send to the assistant
    prompts =[] 
    prompts.append(prompt2)
    prompts.append(prompt)

  
    tf = False  # Safety varaible
    successful_messages = [] # Succesfull messages get pushed to this arrray 
    count = 0
    while(tf == False): # Loop to keep prompting the assistant untill all the messages have went through succesfully 
      messages = await promptAssistant(client, prompts)  # Sending the prompts to the assistant
      try:          # Try and catch because sometimes GPT fails to complete the response for some of the prompts so we have check by accessing a field that is only returned if the response was complete, otherwise if we try to access a field that doesnt have this data field existing it will throw an error which we will force gpt to restart the failed prompt
        for message in messages:
          print(message.data[0].file_ids[0]) # Our code breaker right here. If the prompt was succesfull then this field would exist. Otherwise we will get an error.
          successful_messages.append(message) # If the above code doesnt break we will push the prompt response to this array to mark it as complete
          count = count + 1 # This is our tracker for which message we are currently working with 
        tf = True  # If all messages go through, this is our loop breaker 
      except Exception as e: # Catch statement to detect broken prompt responses
        mess = str(messages[count].data[len(messages[0].data) -1].content[0]) # Extarcting the replies back from gpt
        match = re.search(r'value="(.*?)"', mess) # Seeing if the prompt reply was succesfull. This field would exist if it was.
        if match:    # If there was a match 
          value_attribute = match.group(1)
          for prompt in prompts:
            if prompt == value_attribute:
              prompts.remove(prompt) # Remove the completed prompt
        else:
          print("Value attribute not found.") 
          
  
    count = 0
    for message in successful_messages:  # After all prompts are completed save all the files that are needed for analysis 
      json_file_response = client.files.retrieve_content(file_id=message.data[0].file_ids[0])
      jsonObj = json.loads(json_file_response)
      count = count + 1       
      filename = f'output{count}.json'
      with open(filename, 'w') as file:
        json.dump(jsonObj, file, indent=4)

        
    scriptAPTIOCAnalysisFunc()  # The real analysis comes from this function. Based on threat actors attributes such as the countries they target, countries they operate in, industries they target we can corelate them to IOC's. Each match is assigned a precentage.


  

   


asyncio.run(main())


