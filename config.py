import os #import means go grab this tool and bring it into my file so I can use it.
from dotenv import load_dotenv #from dotenv import load_dotenv means go grab the load_dotenv function from the dotenv library.

#() means we are calling the function load_dotenv without any arguments, which will look for a .env file in the current directory.
load_dotenv() #load_dotenv() means go find the .env file and load the environment variables into the system so we can access them using os.getenv()


VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY") #VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY") means go get the value of the environment variable named "VIRUSTOTAL_API_KEY" and store it in the variable VIRUSTOTAL_API_KEY.
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY") #URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY") means go get the value of the environment variable named "URLSCAN_API_KEY" and store it in the variable URLSCAN_API_KEY.

VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3"
URLSCAN_URL = "https://urlscan.io/api/v1"

RATE_LIMIT_DELAY = 20 #rate limit delay is the amount of time we need to wait between API calls to avoid hitting the rate limit of the API. This is important because if we hit the rate limit, we will get an error and our program will not work. The rate limit delay is usually specified in the API documentation, and it is usually a few seconds. In this case, we are setting it to 15 seconds to be safe.# Delay in seconds to respect API rate limits

