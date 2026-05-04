import os
from groq import Groq

#The API key
client = Groq(
	api_key = "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"
)

#This functions sends requests to the API and stores the response
def llm_request(data):
	completions = client.chat.completions.create(
		model = "llama-3.3-70b-versatile",
		messages = [
			{
			"role":"user",
			"content":f""" You are a cybersecurity analyst working with an IDS.
			
When an packet is flagged you will be tasked in conducting research and creating a incident report report (150 words). When displaying the report use headings (No introduction). This report should cover the following:


	1. Why has this packet been flagged?
	2. What methods can be recommended to mitigate the risks?
	3. Allocate a priority level (low/medium/high/critical)


Use the data provided to develop the report and then conduct research on the IP address searching for:
	1. Why is it deemed malicous?
	2. Where has it been used prior?

However if there is a lack of data to determine a conclusion just state "Insufficient data"

Use this data : {data}
"""

			}
		],
		#Hyperparameters
		temperature = 0.5,
		max_completion_tokens=1024,
		top_p = 0.3,
		stop=None
	)
	report = completions.choices[0].message.content
	#Stores the response in the dictionary
	data['report'] = report
			
