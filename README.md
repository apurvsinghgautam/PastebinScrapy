# Pastebin Scraping


This is a Web Scraping application built on Flask. This web application utilizes Pastebin Scraping API and scrapes IOCs including IP addresses, hashes, and emails from latest pastes of Pastebin. Kibana is also used for visualizing data from Elasticsearch database.


![Pastebin Scraping Homepage](https://user-images.githubusercontent.com/20106707/39991641-d14dcbe6-578d-11e8-9b41-82926273694b.png)


## Prerequisites

- Python
- Flask
- Requests
- Elasticsearch 5.6
- BeautifulSoup
- Kibana


## Usage

- Enter your Pastebing Scraping API key and Flask secret key in the code
- Run the `PastebinScraping.py` file
- Open `127.0.0.1:5000` in any browser
- Open `127.0.0.1:5601` in any browser to see the Kibana dashboard


## Screenshots

![Pastebin Scraping Latest Paste](https://user-images.githubusercontent.com/20106707/40423043-f09937c4-5eae-11e8-9f30-da276409d6f1.png)

![Pastebin Scraping Hostaname](https://user-images.githubusercontent.com/20106707/40050475-3cd0bd2a-5855-11e8-99e9-2f2deb91bfed.png)

![Pastebin Scraping Detailed](https://user-images.githubusercontent.com/20106707/78074932-9ebe6d00-7371-11ea-86e5-0acd81e9fdb0.png)

![Kibana Dashboard](https://user-images.githubusercontent.com/20106707/78077375-49388f00-7376-11ea-9bfb-9221c0141bc1.png)

## Contributors

- [Apurv Singh Gautam](https://apurvsinghgautam.me)
