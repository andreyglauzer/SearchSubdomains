#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

__author__ = 'Andrey Glauzer'
__version__ = "0.1.0"

import censys.certificates
from ipaddress import ip_network, ip_address
import geoip2.database
import censys.ipv4
import yaml
from functools import reduce
import censys
import socket
import time
import requests
from datetime import datetime, timedelta, date
import json
import os
import csv
import logging
import argparse
import base64
import sqlite3
import collections
import urllib.request

class DataBase:
	def __init__(self,
		database_path=None,
		database_name=None,
		):

		self.logger = logging.getLogger('Database')
		self.logger.info('Checking Database.')

		self.database_path = database_path
		self.database_name = database_name

		if not os.path.exists('{path}/{filename}'.format(path=self.database_path, filename=self.database_name)):
			conn = sqlite3.connect('{path}/{filename}'.format(path=self.database_path, filename=self.database_name))
			cursor = conn.cursor()

			cursor.execute('CREATE TABLE IF NOT EXISTS DOMAINNAMES ( id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,'
			'domain TEXT, type TEXT, subdomain TEXT, local TEXT, status_code TEXT, ipv4 TEXT, autonomous_system_number TEXT, autonomous_system_organization TEXT, iso_code TEXT, country_name TEXT, most_specific TEXT, city_name TEXT, latitude TEXT, longitude TEXT);')

			conn.commit()
			conn.close()
		else:
			conn = sqlite3.connect('{path}/{filename}'.format(path=self.database_path, filename=self.database_name))
			cursor = conn.cursor()

			cursor.execute('CREATE TABLE IF NOT EXISTS DOMAINNAMES ( id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,'
			'domain TEXT, type TEXT, subdomain TEXT, local TEXT, status_code TEXT, ipv4 TEXT, autonomous_system_number TEXT, autonomous_system_organization TEXT, iso_code TEXT, country_name TEXT, most_specific TEXT, city_name TEXT, latitude TEXT, longitude TEXT);')

			conn.commit()
			conn.close()


	def compare(self,
		subdomain=None):
		"""
			In order not to generate unnecessary requests anymore, a comparison is made in a sqllite database, preventing it from making requests, in subdomains that we already have information.
		"""
		self.logger.debug('Comparing SCAN with what you already have in the database.')
		conn = sqlite3.connect('{path}/{filename}'.format(path=self.database_path, filename=self.database_name))
		cursor = conn.cursor()
		r = cursor.execute("SELECT * FROM DOMAINNAMES WHERE subdomain='{subdomain}';".format(subdomain=subdomain))

		return r.fetchall()


	def save(self,
		domain=None,
		type=None,
		subdomain=None,
		local=None,
		status_code=None,
		ipv4=None,
		autonomous_system_number=None,
		autonomous_system_organization=None,
		iso_code=None,
		country_name=None,
		most_specific=None,
		city_name=None,
		latitude=None,
		longitude=None):
		"""
			If the subdomain does not exist in the database, it is saved.
		"""
		self.logger.debug('Saving the SUBDOMAINS in the database..')
		conn = sqlite3.connect('{path}/{filename}'.format(path=self.database_path, filename=self.database_name))
		cursor = conn.cursor()
		cursor.execute("""
		INSERT INTO DOMAINNAMES (domain, type, subdomain, local, status_code, ipv4, autonomous_system_number, autonomous_system_organization, iso_code, country_name, most_specific, city_name, latitude, longitude)
		VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')
		""" % (domain, type, subdomain, local, status_code, ipv4, autonomous_system_number, autonomous_system_organization, iso_code, country_name, most_specific, city_name, latitude, longitude))
		conn.commit()
		conn.close()

class GetDomains:
	def __init__(self,
		apid=None,
		secret=None,
		database_path=None,
		database_name=None,
		splunk_dir=None,
		debug=None,
		checkcidr=None,
		CIDR=None,
		target=None):

		self.apid = apid
		self.secret = secret
		self.database_path = database_path
		self.database_name = database_name
		self.splunk_dir = splunk_dir
		self.debug = debug
		self.checkcidr = checkcidr
		self.CIDR = CIDR
		self.target = target

		self.database = DataBase(database_path=self.database_path,
			database_name=self.database_name ,)

		if debug:
			logging.basicConfig(
					level=logging.INFO,
					format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
					datefmt='%Y-%m-%d %H:%M:%S',
			)
		else:
			logging.basicConfig(
					level=logging.DEBUG,
					format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
					datefmt='%Y-%m-%d %H:%M:%S',
			)

		self.logger = logging.getLogger('XP Domains name')

		self.censys_certificates = censys.certificates.CensysCertificates(api_id=self.apid, api_secret=self.secret)
		self.session = requests.session()

	def subs(self, domain=None):
		"""
			Obtains all subdomains from the censys.io site through the SSL certificate and WildCard used by the company.
			To get subdomains the free API version, which has a daily limit, is used. For more information go to https://censys.io/demo-request
		"""
		if domain is not None:
			try:
				certificate_query = 'parsed.names: %s' % domain
				certificates_search_results = self.censys_certificates.search(certificate_query, fields=['parsed.subject.common_name'])

				subdomains = []
				for search_result in certificates_search_results:
					subdomains.extend(search_result['parsed.subject.common_name'])

				return subdomains
			except:
				self.logger.error('You have reached Censys daily limit, renew your Token, as some subdomains may not be found.')
				pass


	def getlocal(self, ip=None):
		"""
			Some names are resolved internally, and to know where you are, a hint is made, pointing to
			CIDR and the name of the location where it is located. This also serves for public addresses..
		"""
		if ip is not None:
			for cidr in self.CIDR:
				for ranges in cidr['group']['id'].split(','):
					if ip_address(ip) in ip_network(ranges):
						return cidr['group']['name']

	def replaces_text(self, raw=None):
		"""
			In order not to generate line breaks or information that harm the database, some replaces are done.
		"""
		if raw is not None:
			repls = (
				('\n', r''),
				('\r', r''),
				('\t', r''),
				('\s', r''),
			)
			data = reduce(lambda a, kv: a.replace(*kv), repls, raw)

			return data

	@property
	def start(self):
		self.logger.info('Getting the domain target.')
		with open(self.target, 'r') as stream:
			for line in stream:
				self.logger.info('Searching for subdomains of {}'.format(self.replaces_text(raw=line)))
				templist = []
				self.logger.debug('Clearing variables.')
				type = None
				sub = None
				local = None
				status_code = None
				ipv4 = None
				autonomous_system_number = None
				autonomous_system_organization = None
				iso_code = None
				country_name = None
				most_specific = None
				city_name = None
				latitude = None
				longitude = None

				name = self.replaces_text(raw=line)
				self.logger.info('Getting subdomains in censys.')
				list = self.subs(domain=name)
				self.logger.debug('Clearing information and removing duplicates.')
				if list is not None:
					mylist = self.clearlist(
						list=list,
						domain=name)
					templist.extend(mylist)
				# Resolve os nomes, para obter os endereços IPS
				self.logger.info('Getting subdomains from VirusTotal.')
				virustotallist = self.virustotal(domain=name)
				templist.extend(self.removeDuplicate(list=virustotallist))

				self.logger.info('Getting information from all subdomains found. WAIT...')
				for sub in templist:
					if self.database.compare(subdomain=sub):
						self.logger.debug('The domain {} is already in the database.'.format(sub))
					else:
						if 'Not Found' in self.getmyIP(domain=sub):
							status_code = "404"
						else:
							try:
								type = "Public"
								local = self.getlocal(ip=self.getmyIP(domain=sub))
								try:
									status_code = urllib.request.urlopen("http://"+sub).getcode()
								except (ConnectionResetError,urllib.error.URLError) as e:
									status_code = "404"
								reader = geoip2.database.Reader('utils/GeoLite2-ASN.mmdb')
								response = reader.asn(self.getmyIP(domain=sub))

								autonomous_system_number = response.autonomous_system_number
								autonomous_system_organization = response.autonomous_system_organization

								reader = geoip2.database.Reader('utils/GeoLite2-City.mmdb')
								response = reader.city(self.getmyIP(domain=sub))

								iso_code = response.country.iso_code
								country_name = response.country.name
								most_specific = response.subdivisions.most_specific.name
								city_name = response.city.name
								latitude = response.location.latitude
								longitude = response.location.longitude


							except (geoip2.errors.AddressNotFoundError) as e:
								local = self.getlocal(ip=str(self.getmyIP(domain=sub)))
								type = "Private"
								try:
									status_code = urllib.request.urlopen("http://"+sub).getcode()
								except (ConnectionResetError,urllib.error.URLError) as e:
									status_code = "404"

							type = type if type is not None else "Null"
							sub = sub if sub is not None else "Null"
							local = local if local is not None else "Null"
							status_code = status_code if status_code is not None else "Null"
							ipv4 = self.getmyIP(domain=sub) if self.getmyIP(domain=sub) is not None else "Null"
							ASN = "ASN{}".format(autonomous_system_number) if autonomous_system_number is not None else "Null"
							autonomous_system_organization = autonomous_system_organization if autonomous_system_organization is not None else "Null"
							iso_code = iso_code if iso_code is not None else "Null"
							country_name = country_name if country_name is not None else "Null"
							most_specific = most_specific if most_specific is not None else "Null"
							city_name = city_name if city_name is not None else "Null"
							latitude = latitude if latitude is not None else "Null"
							longitude = longitude if longitude is not None else "Null"

							data ={
								"domain": name,
								"type": type,
								"subdomain": sub,
								"local": local,
								"status_code": status_code,
								"ipv4": ipv4,
								"autonomous_system_number": ASN,
								"autonomous_system_organization": autonomous_system_organization,
								"iso_code": iso_code,
								"country_name": country_name,
								"most_specific": most_specific,
								"city_name":city_name,
								"latitude": latitude,
								"longitude": longitude,
							}

							self.logger.debug('Saving the domain {} in the database.'.format(sub))
							self.database.save(
								domain=name,
								type=type,
								subdomain=sub,
								local=local,
								status_code=status_code,
								ipv4= ipv4,
								autonomous_system_number=ASN,
								autonomous_system_organization=autonomous_system_organization,
								iso_code=iso_code,
								country_name=country_name,
								most_specific=most_specific,
								city_name=city_name,
								latitude=latitude,
								longitude=longitude)

							self.logs_save_splunk = '{0}/finish-splunk-domainsnames-{1}.json'.format(self.splunk_dir, datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f"))

							self.logger.info('Saving file to {}.'.format(self.logs_save_splunk))
							if not os.path.exists(self.logs_save_splunk):
								arquivo = open(self.logs_save_splunk, 'w', encoding="utf-8")
								arquivo.close()

							arquivo = open(self.logs_save_splunk, 'r', encoding="utf-8")
							conteudo = arquivo.readlines()
							conteudo.append(json.dumps(data, ensure_ascii=False)+'\n')
							arquivo = open(self.logs_save_splunk, 'w', encoding="utf-8")
							arquivo.writelines(conteudo)
							arquivo.close()


	def getmyIP(self,domain=None):
		"""
			To get additional information about the subdomain, you need to convert it to IPV4.
		"""
		if domain is not None:
			try:
				self.logger.debug('Getting IPV4 Address from Domain {}'.format(domain))
				return socket.gethostbyname(domain)
			except (socket.gaierror) as e:
				self.logger.debug('Could not get domain IPV4 address {}'.format(domain))
				return 'Not Found'


	def virustotal(self, domain=None):
		"""
			The virustotal API is used, for more subdomains, this is not the paid way to get information.
			So it is somewhat limited, if you misuse it, you'll need to go through a recap, but don't worry,
			I'll have warn you when that happens.

			There is also a daily limit, which I am not sure how much it is, because I use the same requests that the site makes.
		"""
		if domain is not None:
			self.logger.debug('Getting VirusTotal Information')
			request = self.session.get('https://www.virustotal.com/ui/domains/{}/subdomains?relationships=resolutions'.format(domain))
			datajson = json.loads(request.content)
			names = []
			try:
				try:
					myerror = datajson['message']
					self.logger.error('Something went wrong with the VirusTotal API. I believe it may be the capcha or we have exceeded the daily limit.\nError: {}'.format(myerror))
					exit(0)
				except:
					myerror = datajson['error']
					self.logger.error('Something went wrong with the VirusTotal API. I believe it may be the capcha or we have exceeded the daily limit.\nError: {}'.format(myerror))
					exit(0)
			except (KeyError) as e:
				try:
					for subs in datajson['data']:
						names.append(subs['id'])
					count = 0
					while count <= 90:
						try:
							count = count+10
							decode = "I%s\n." % (count)
							url = 'https://www.virustotal.com/ui/domains/{domain}/subdomains?relationships=resolutions&cursor={cursor}%3D&limit=40'.format(
								cursor=base64.b64encode(decode.encode('utf-8')).decode('UTF-8').replace('=',''),
								domain=domain)

							request = self.session.get(url)
							datajson = json.loads(request.content)
							for subs in datajson['data']:
								names.append(subs['id'])
						except (KeyError) as e:
							pass
				except (KeyError) as e:
					pass

				return names

	def removeDuplicate(self,list=None):
		"""
			Before getting information on subdomains I make a list of everything I already have, to avoid making too many requests
			in the APIs and eventually reach my limit, I clean up duplicate items.
		"""
		self.logger.debug('Remove Duplicate Names from List.')
		if list is not None:
			return [el for i, el in enumerate(list) if el not in list[:i]]

	def clearlist(self, list=None, domain=None):
		"""
			Some more information may come together, and sometimes some domains that are not our scope, so they should be removed here.
		"""
		self.logger.debug('Performing cleanup of information that is not required.')
		if list is not None:
			itens = [
				'incapsula.com',
				'*.{}'.format(domain),
				'.pantheonsite.io'
			]

			listOfitens = [ elem for elem in list if elem not in itens ]

			return listOfitens

class GetConfigs:
	def __init__(self):
		logging.basicConfig(
				level=logging.INFO,
				format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
				datefmt='%Y-%m-%d %H:%M:%S',
		)
		self.logger = logging.getLogger('Get Configs')

		parser = argparse.ArgumentParser()

		parser.add_argument('-c', '--config', help='The directory of the settings file, in Yaml format.',
						   action='store', dest = 'config')
		parser.add_argument('-t', '--target', help='Enter the file location, where you have all the domains you want to verify.',
						   action='store', dest = 'target')

		args = parser.parse_args()
		self.config = args.config
		self.target = args.target

	@property
	def start(self):
		if os.path.exists(self.config):
			if '.yml' in self.config:
				with open(self.config, 'r') as stream:
					data = yaml.load(stream, Loader=yaml.FullLoader)
					self.apid = data.get('apid', '')
					self.secret = data.get('secret', '')
					self.database_path = data.get('database_path', '')
					self.database_name = data.get('database_name', '')
					self.splunk_dir = data.get('splunk_dir', '')
					self.debug = data.get('debug', '')
					self.checkcidr = data.get('checkcidr', '')
					self.CIDR = data.get('CIDR', '')

					if self.debug:
						logging.basicConfig(
								level=logging.DEBUG,
								format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
								datefmt='%Y-%m-%d %H:%M:%S',
							)
					else:
						logging.basicConfig(
							level=logging.INFO,
							format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
							datefmt='%Y-%m-%d %H:%M:%S',
						)

					get = GetDomains(apid=self.apid,
						secret=self.secret,
						database_path=self.database_path,
						database_name=self.database_name,
						splunk_dir=self.splunk_dir,
						debug=self.debug,
						checkcidr=self.checkcidr,
						CIDR=self.CIDR,
						target=self.target)
					get.start

			else:
				self.logger.error('Entered file type is not valid, must be of format yml.\n')
				sys.exit(1)
		else:
			self.logger.error('File does not exist or path is incorrect.\n')
			sys.exit(1)


GetConfigs().start
