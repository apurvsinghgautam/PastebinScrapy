# PastebinScrapy

![https://img.shields.io/github/stars/apurvsinghgautam/PastebinScrapy](https://img.shields.io/github/stars/apurvsinghgautam/PastebinScrapy) ![https://img.shields.io/github/forks/apurvsinghgautam/PastebinScrapy](https://img.shields.io/github/forks/apurvsinghgautam/PastebinScrapy)

[![forthebadge](https://forthebadge.com/images/badges/made-with-python.svg)](https://forthebadge.com)

This is a Threat Hunting tool built on Flask. This tool utilizes Pastebin Scraping API and scrapes IOCs including IP addresses, domains, hashes, and emails from latest pastes of Pastebin. It uses Elasticsearch as the database to store the pastes and Kibana is used for visualizing data from Elasticsearch.


![PastebinScrapy Homepage](https://user-images.githubusercontent.com/20106707/39991641-d14dcbe6-578d-11e8-9b41-82926273694b.png)


## Prerequisites

- Python
- Flask
- Requests
- Elasticsearch 5.6
- BeautifulSoup
- Kibana


## Usage

- Enter your Pastebing Scraping API key and Flask secret key in the code
- Run the `PastebinScrapy.py` file
- Open `127.0.0.1:5000` in any browser
- Open `127.0.0.1:5601` in any browser to see the Kibana dashboard


## Screenshots

![PastebinScrapy Latest Paste](https://user-images.githubusercontent.com/20106707/40423043-f09937c4-5eae-11e8-9f30-da276409d6f1.png)

![PastebinScrapy Hostaname](https://user-images.githubusercontent.com/20106707/40050475-3cd0bd2a-5855-11e8-99e9-2f2deb91bfed.png)

![PastebinScrapy Detailed](https://user-images.githubusercontent.com/20106707/78074932-9ebe6d00-7371-11ea-86e5-0acd81e9fdb0.png)

![Elasticsearch Paste data](https://user-images.githubusercontent.com/20106707/78078184-af71e180-7377-11ea-9b4e-e72c014c8478.png)

![Kibana Dashboard](https://user-images.githubusercontent.com/20106707/78077375-49388f00-7376-11ea-9bfb-9221c0141bc1.png)

## Contributors

- [Apurv Singh Gautam](https://apurvsinghgautam.me)
