import re
import socket
import json
import time
import hashlib
import requests
from flask import *
from threading import *
from functools import wraps
from bs4 import BeautifulSoup
from logging.config import dictConfig
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import TransportError

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'formatter': 'default'
    }},
    'root': {
        'level': 'DEBUG',
        'handlers': ['wsgi']
    }
})

app = Flask(__name__)

'''
This function gets the latest paste from the Pastebin website, stores it in the database.
The thread keeps running indefinitely
'''
@app.before_first_request
def activate_job():
	def run_job():
		try:
			bin=Pastebin()
		except (Exception, IOError) as e:
			app.logger.error(e)

		pastes={
			'settings': {
				'analysis': {
					'analyzer': {
						'my_title_analyzer': {
							'type':'pattern',
							'pattern': '\\W|_'
						}
					}
				}
			},
			'mappings': {
				'pastes': {
					'properties': {
						'paste_id': {'type':'keyword'},
						'paste_date': {'type':'text'},
						'paste_title': {'analyzer':'my_title_analyzer', 'type':'text'},
						'paste_size': {'type':'text'},
						'paste_url': {'type':'keyword'},
						'raw_paste': {'type':'text'}
					}
				}
			}
		}
		ip_paste_data={
			'mappings': {
				'ip_paste_data': {
					'properties': {
						'paste_id': {'type':'keyword'},
						'ip': {'type': 'ip'},

					}
				}
			}
		}
		email_paste_data = {
			'mappings': {
				'email_paste_data': {
					'properties': {
						'paste_id': {'type': 'keyword'},
						'email': {'type': 'keyword'}
					}
				}
			}
		}
		hash_paste_data = {
			'mappings': {
				'hash_paste_data': {
					'properties': {
						'paste_id': {'type': 'keyword'},
						'md5_hash': {'type': 'keyword'},
						'sha256_hash': {'type': 'keyword'}
					}
				}
			}
		}
		domain_paste_data = {
			'mappings': {
				'domain_paste_data': {
					'properties': {
						'paste_id': {'type': 'keyword'},
						'domain': {'type': 'keyword'}
					}
				}
			}
		}
		users={
			'mappings': {
				'users': {
					'properties': {
						'name': {'type':'text'},
						'email': {'type':'keyword'},
						'password': {'type':'keyword'}
					}
				}
			}
		}

		try:
			if bin.get_elastic().indices.exists('pastes'):
				pass
			else:
				bin.create_index('pastes',pastes)

			if bin.get_elastic().indices.exists('ip_paste_data'):
				pass
			else:
				bin.create_index('ip_paste_data',ip_paste_data)

			if bin.get_elastic().indices.exists('email_paste_data'):
				pass
			else:
				bin.create_index('email_paste_data',email_paste_data)

			if bin.get_elastic().indices.exists('hash_paste_data'):
				pass
			else:
				bin.create_index('hash_paste_data',hash_paste_data)

			if bin.get_elastic().indices.exists('domain_paste_data'):
				pass
			else:
				bin.create_index('domain_paste_data',domain_paste_data)

			if bin.get_elastic().indices.exists('users'):
				pass
			else:
				bin.create_index('users',users)
		except (Exception, IOError, TransportError) as e:
			app.logger.error(e)

		while True:
			try:
				latest=bin.get_latest_paste()
				paste=json.loads(bin.parse_json(latest))
			except:
				app.logger.warning("Connection refused by the server")
				app.logger.warning("Retrying in few seconds")
				time.sleep(60)
				continue
			for p in paste:
				if is_visited(p):
					continue
				else:
					app.logger.info("Parsing Data")
					try:
						data=parse_data(p)
					except:
						app.logger.warning("Connection refused by the server")
						app.logger.warning("Retrying in few seconds")
						time.sleep(60)
						continue

					if data:
						hname=[]
						if 'ip' in data.keys():
							app.logger.info("Parsing Hostname")
							hname=resolve_hostname(data['ip'])
						try:
							raw='\n'.join(get_raw(p))
						except:
							app.logger.warning("Connection refused by the server")
							app.logger.warning("Retrying in few seconds")
							time.sleep(60)
							continue

						paste_data={
							'paste_id': p['paste_key'],
							'paste_date': epoch_to_utc(p['paste_date']),
							'paste_title': p['paste_title'],
							'paste_size': p['paste_size'],
							'paste_url': p['paste_url'],
							'raw_paste': raw
						}
						try:
							app.logger.info("Storing Data")
							bin.get_elastic().index(index='pastes', doc_type='pastes', body=paste_data)
							if len(hname) != 0:
								for ip_host_data in hname:
									p_data={
										'paste_id': p['paste_key'],
										'ip': ip_host_data.split(':')[0],
										'host': ip_host_data.split(':')[1]
									}
									bin.get_elastic().index(index='ip_paste_data', doc_type='ip_paste_data', body=p_data)

							for key in data.keys():
								if key == 'email':
									for email in data[key]:
										p_data={
											'paste_id': p['paste_key'],
											'email': email
										}
										bin.get_elastic().index(index='email_paste_data', doc_type='email_paste_data', body=p_data)

								elif key == 'md5_hash':
									for md5_hash in data[key]:
										p_data={
											'paste_id': p['paste_key'],
											'md5_hash': md5_hash
										}
										bin.get_elastic().index(index='hash_paste_data', doc_type='hash_paste_data', body=p_data)

								elif key == 'domain':
									for domain in data[key]:
										p_data={
											'paste_id': p['paste_key'],
											'domain': domain
										}
										bin.get_elastic().index(index='domain_paste_data', doc_type='domain_paste_data', body=p_data)

						except (Exception, IOError, TransportError) as e:
							app.logger.error(e)
	try:					
		thread=Thread(target=run_job)
		thread.start()
	except (Exception, IOError):
		app.logger.error("Caught an exception in thread")

'''
This function displays Home page of the Pastebin Scrapy
'''
@app.route('/')
def index():
	return render_template("index.html")


class Pastebin():

	def __init__(self):
		self.__es=Elasticsearch()
		self.__api_key='<your_api_key>'
		self.__api_url='https://pastebin.com/api/api_post.php'

	#This function creates pastes index
	def create_index(self,index,data):
		self.__es.indices.create(index=index, body=data)

	#This function returns elasticsearch object
	def get_elastic(self):
		return self.__es

	#This function gets the latest paste from the Pastebin website	
	def get_latest_paste(self):
		data={'api_dev_key':self.__api_key,'api_option':'trends'}
		r=requests.post(self.__api_url,data=data)
		return r.text
	
	#This function parses the data from the Pastebin website into JSON format
	def parse_json(self,data):
		latest_post={}
		posts=[]
		for item in data.split('\r\n'):
			if "<paste>" in item:
				pass
			if "<paste_" in item:
				sub_item=item.split('>')
				latest_post.update({sub_item[0].split('<')[1]:sub_item[1].split('<')[0]})
			if "</paste>" in item:
				posts.append(latest_post)
				latest_post={}	
		return json.dumps(posts,sort_keys=True, indent=4)

	
'''
This function takes user credentials at the time of registration and stores the details in the database
'''
@app.route('/register', methods=['GET','POST'])
def register():
	if request.method == 'POST':
		name=request.form['name']
		email=request.form['email']
		password=hashlib.sha256(str(request.form['password'])).hexdigest()
		bin=Pastebin()
		data={
			'query': {
				'match': {
					'email': email
				}
			}
		}

		try:
			res=bin.get_elastic().search(index='users', body=data)
			if len(res['hits']['hits']) != 0:
				flash('Email Already Registered','msg')
				return redirect(url_for('register'))
			else:
				bin.get_elastic().index(index='users', doc_type='users', body={'name':name, 'email':email, 'password':password})
		except (Exception, IOError, TransportError) as e:
			app.logger.error(e)

		flash('You are now registered and can log in','success')
		return redirect(url_for('login'))
	return render_template('auth/register.html')


'''
This function takes user credentials at the time of login and authenticates the user
'''
@app.route('/login', methods=['GET','POST'])
def login():
	if request.method == 'POST':
		email=request.form['email']
		password_candidate=hashlib.sha256(str(request.form['password'])).hexdigest()
		bin=Pastebin()
		data={
			'query': {
				'match': {
					'email': email
				}
			}
		}

		try:
			res=bin.get_elastic().search(index='users', body=data)
			if len(res['hits']['hits']) != 0:
				#Get stored password hash
				name=res['hits']['hits'][0]['_source']['name']
				email=res['hits']['hits'][0]['_source']['email']
				password=res['hits']['hits'][0]['_source']['password']

				#Compare Passwords
				if password_candidate == password:
					session['logged_in']=True
					session['name']=res['hits']['hits'][0]['_source']['name']
					session['email']=res['hits']['hits'][0]['_source']['email']
					flash('You are now logged in','success')
					return redirect(url_for('index'))
				else:
					error='Invalid Email/Password'
					return render_template('auth/login.html',error=error)
			else:
				error='Invalid Email/Password'
				return render_template('auth/login.html',error=error)
		except (Exception, IOError, TransportError) as e:
			app.logger.error(e)
	return render_template('auth/login.html')


'''
This function is used to check whether a session is valid or not
'''
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap


'''
This function is used to invalidate the session and logout the user
'''
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


'''
This function is used to get the latest paste information from the database
'''
@app.route('/get_latest_paste/<string:page>')
@is_logged_in
def get_latest_paste(page):
	bin=Pastebin()
	data={
		'from': ((decode(page)-1)*10),
		'size': 10,
		'query': {
			'match_all':{

			}
		}
	}

	if decode(page) <= 0:
		return render_template('404.html')
	else:
		try:
			res=bin.get_elastic().search(index='pastes', body=data)
			if res['hits']['hits'] is None:
				flash('No Data Found','danger')
				return render_template("get_latest_paste.html",lpaste=[], page=page)
			else:
				return render_template("get_latest_paste.html",lpaste=res, page=page)
		except (Exception, IOError, TransportError) as e:
			app.logger.error(e)
    

'''
This function is used to get resolved hostnames and IP addresses from the database
'''
@app.route('/get_paste_data/<string:id>/<string:page>')
@is_logged_in
def get_paste_data(id,page):
	bin=Pastebin()
	data={
		'from': ((decode(page)-1)*10),
		'size': 10,
		'query': {
			'match':{
				'paste_id': id
			}
		}
	}

	if decode(page) <= 0:
		return render_template('404.html')
	else:
		try:
			ip_paste_data_res=bin.get_elastic().search(index='ip_paste_data', body=data)
			email_paste_data_res=bin.get_elastic().search(index='email_paste_data', body=data)
			paste_res=bin.get_elastic().search(index='pastes', body={'query':{'match':{'paste_id':id}}})
			return render_template("get_paste_data.html", details=paste_res, hosts=ip_paste_data_res, email=email_paste_data_res, page=page, id=id)
		except (Exception, IOError, TransportError) as e:
			app.logger.error(e)


'''
This function is used to get searched pastes
'''
@app.route('/search_paste', methods=['GET','POST'])
@is_logged_in
def search_paste():
	if request.method == 'POST':
		search_text=request.form['search']
		bin=Pastebin()
		data={
			'query': {
				'match': {
					'paste_title': search_text
				}
			}
		}

		if not search_text:
			return render_template('get_searched_paste.html')
		else:
			try:
				res=bin.get_elastic().search(index='pastes', body=data)
				if res['hits']['hits'] is None:
					return render_template("get_searched_paste.html",lpaste=[])
				else:
					return render_template("get_searched_paste.html",lpaste=res)
			except (Exception, IOError, TransportError) as e:
				app.logger.error(e)


'''
This function is used to encode string using Base64 and is called during context processing in Jinja2
'''
@app.context_processor
def utility_processor():
	def encode(data):
		return str(data).encode('base64').strip('\r\n')
	return dict(encode=encode)	

#This function is used to convert time integer to UTC format
def epoch_to_utc(data):
	return time.strftime('%Y-%b-%d %H:%M:%S', time.gmtime(float(data)))

#This function is used to parse the IP, Email, Domain, Phone and Hash from a particular paste
def parse_data(data):
	d={}
	r=requests.get(data['paste_url'])
	data_regex={
		'ip': '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',
		'email': '[A-Za-z0-9\.\-+_]+@[A-Za-z0-9\.\-+_]+\.[a-z]+',
		'domain': '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$',
		'md5_hash': '^[a-f0-9]{32}$'
	}
	for key in data_regex.keys():
		match=re.findall(data_regex[key], r.text)
		if match:
			match = list(set(match))
			d[key] = match
	return d

#This function is used to resolve the hostname from the collected IP address of a particular paste
def resolve_hostname(data):
	hname=[]
	if len(data) != 0:
		for ipaddr in data:
			if ip_to_host(ipaddr) == ipaddr:
				hname.append(ipaddr+":-")
			else:
				hname.append(ipaddr+":"+ip_to_host(ipaddr))
	return hname

#This function is used to resolve hostname from IP address
def ip_to_host(data):
	return socket.getfqdn(data)

#This function is used to get the RAW data from a particular paste
def get_raw(data):
	raw=[]
	r=requests.get(data['paste_url'])
	soup=BeautifulSoup(r.text,'html.parser')
	if soup.textarea.string:
		for item in soup.textarea.string.split('\r\n'):
			raw.append(item)
	return raw

#This function is used to check whether the paste URL is already visited by the program or not
def is_visited(data):
	bin=Pastebin()
	data={
		'query': {
			'match': {
				'paste_id': data['paste_key']
			}
		}
	}
	try:
		res=bin.get_elastic().search(index='pastes', body=data)
		if len(res['hits']['hits']) != 0:
			return True
		else:
			return False
	except (Exception, IOError, TransportError) as e:
		app.logger.error(e)

#This function encodes the string using Base64
def encode(data):
	return str(data).encode('base64').strip('\r\n')

#This function decodes the string using Base64
def decode(data):
	return int(data.decode('base64'))


if __name__ == '__main__':
	app.secret_key = '<your_secret_key>'
	app.run(debug=True)
