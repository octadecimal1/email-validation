import urllib.request
import socket
import smtplib
import dns.resolver
import logging
import re
import tldextract


JUNK_EMAIL_LOCAL_1 = 'j342jh342hj342hj342hj342h342b2h4bjh24b3234j32'
JUNK_EMAIL_LOCAL_2 = 'gfx3gf4x46g7x5yfusx7fx7f6x98f8b7xz9f7z69dz76d'
JUNK_EMAILS = [JUNK_EMAIL_LOCAL_1, JUNK_EMAIL_LOCAL_2]


class EmailVerification:

	def check_syntax(self, email_address):
		"""
		Does regex based syntax check of email address based on RFC guidelines
		"""

		regex = r"^([!#-\'*+\/-9=?A-Z^-~\\\\-]{1,64}(\.[!#-\'*+\/-9=?A-Z^-~\\\\-]{1,64})*|\"([\]!#-[^-~\ \t\@\\\\]|(\\[\t\ -~]))+\")@([0-9A-Z]([0-9A-Z-]{0,61}[0-9A-Za-z])?(\.[0-9A-Z]([0-9A-Z-]{0,61}[0-9A-Za-z])?))+$"

		if re.match(regex, email_address, re.IGNORECASE):
			return True
		else:
			return False


	def get_domain(self, email_address):
		"""
		If syntax is correct, returns the domain name of the email address
		"""
		domain = (email_address.split('@')[-1]).lower()
		if domain.count('.') > 1:
			subdomain = True
		else:
			subdomain = False
		return domain, subdomain


	def validate_domain(self, domain):
		"""
		Expects the domains_master dictionary
		Processes and evaluates domain validity and business name for the domain names with None values
		"""
		url = 'https://' + domain
		tld_result = tldextract.extract(url)
		
		domain_new = tld_result.domain
		subdomain_new = tld_result.subdomain
		suffix = tld_result.suffix

		try:
			socket.gethostbyname(domain)
			domain_valid = True

		except socket.gaierror:
			domain_valid = False

		# getting the (probable) business name of the valid domain names
		business_name = self.get_title(domain)
		domain_type = self.check_domain_type(domain, domain_valid)
		
		return domain_new, domain_valid, subdomain_new, suffix, business_name


	def get_title(self, domain, tries=1):
		"""
		Gets the title from the HTML page that the domain name directs to
		This method tries these combinations- 
		https://www.domain.com
		http://www.domain.com
		www.domain.com
		"""
		# creating opener to act like a actual web browser ping
		opener = urllib.request.build_opener()
		opener.addheaders=[('User-Agent',
							'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko)' \
							'Chrome/36.0.1941.0 Safari/537.36')]
		urllib.request.install_opener(opener)

		try:
			url = 'https://www.' + domain
			
			with urllib.request.urlopen(url, timeout=60) as conn:
				req = conn.read()
		except:
			try:
				url = 'http://www.' + domain
				
				with urllib.request.urlopen(url, timeout=60) as conn:
					req = conn.read()
			except:
				try:
					url = 'www.' + domain
				
					with urllib.request.urlopen(url, timeout=60) as conn:
						req = conn.read()
				except Exception as exc:
					req = ('ERR', exc)

		if type(req) is not tuple:
			try:
				req = req.decode('utf-8').lower()
				title1 = int(req.find('<title')) + 6
				title1 = int(req.find('>', title1)) + 1
				title2 = int(req.find('</title>'))
				title = req[title1:title2]
			except UnicodeDecodeError:
				return 'ERR: Wrong encoding'
		else:
			if tries < 5:
				title = self.get_title(domain, tries+1)
			else:	
				title = str(req[1])

		# handling some weird characters that utf-8 did not handle
		title = title.replace('\n', '').replace('\r', '').replace('\t', '').replace('&#8211;', '-').strip().title()

		if title == '' or title.lower() == 'home' or ('doctype' in title.lower() and 'html' in title.lower()):
			return 'ERR: No title found'
		else:
			return title


	def check_domain_type(self, domain, domain_valid=True):
		"""
		Tries to verify 2 junk email addresses on a domain to decide if that domain
		might be catch all or bouncing off all emails sent to it
		"""

		results = []
		if domain_valid == True:
			for junk_email in JUNK_EMAILS:
				try:
					records = dns.resolver.query(domain, 'MX')
					mxRecord = records[0].exchange
					mxRecord = str(mxRecord)

					host = socket.gethostname()
					server = smtplib.SMTP()
					server.set_debuglevel(0)

					server.connect(mxRecord)
					server.helo(host)
					server.mail('me@domaincc.com')
					email_address = junk_email + '@' + domain
					code, message = server.rcpt(str(email_address))
					results.append((code, message))
					server.quit()

				except Exception as e:
					code = "ERR"
					message = e
					results.append((code, message))

			if str(results[0][0]) == '250' and str(results[1][0]) == '250':
				return 'Catch all'
			
			else:
				return 'Cannot determine'

		else:
			return 'Invalid'


	def verify_email(self, domain, email_address):
		"""
		Actually verifies emails by pinging them, if the domain was valid
		"""
		try:
			records = dns.resolver.query(domain, 'MX')
			mxRecord = records[0].exchange
			mxRecord = str(mxRecord)

			host = socket.gethostname()
			server = smtplib.SMTP()
			server.set_debuglevel(0)

			server.connect(mxRecord)
			server.helo(host)
			server.mail('me@domain.com')
			code, message = server.rcpt(str(email_address))
			server.quit()

		except Exception as e:
			code = "ERR"
			message = e

		return code, message


def validate_email(email_address):

	out = {}
	e = EmailVerification()
	syntax = e.check_syntax(email_address)
	out['email_address_input'] = email_address
	out['syntax'] = syntax
	if syntax:
		domain, subdomain = e.get_domain(email_address)
		out['domain'] = domain
		if subdomain:
			out['subdomain'] = subdomain
		else:
			out['subdomain'] = 'not available'
			subdomain = None
		
		validate_domain_result = e.validate_domain(domain=domain)
		
		out['domain'] = validate_domain_result[0]
		out['domain_type'] = validate_domain_result[1]
		out['subdomain'] = validate_domain_result[2]
		out['suffix'] = '.' + validate_domain_result[3]
		out['business_name'] = validate_domain_result[4]
		
		verify_email_result = e.verify_email(out['domain'] + out['suffix'], email_address)

		if domain.lower() == 'gmail.com' and 'NoSuchUser' in str(verify_email_result[1]):
			out['email_validity_code'] = 'No such user - Gmail'
			out['email_validity_message'] = 'No such user - Gmail'
		else:
			out['email_validity_code'] = verify_email_result[0]
			out['email_validity_message'] = verify_email_result[1]
	else:
		out['domain'] = 'not available'
		out['subdomain'] = 'not available'
		out['domain_type'] = 'not available'
		out['subdomain'] = 'not available'
		out['business_name'] = 'not available'

	return out
