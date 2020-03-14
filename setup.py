from setuptools import setup


def readme():
	with open('README.md') as f:
		README = f.read()
	return README


setup (
	name = 'email-validation',
	version = '1.0.0',
	description = 'A Python package to check the validity of an email address.',
	long_description = readme(),
	long_description_content_type = 'text/markdown',
	url = 'https://github.com/octadecimal1/email-validation',
	author = 'Octadecimal',
	author_email = 'octadecimal1@gmail.com',
	license = 'MIT',
	classifiers = [
		"License :: OSI Approved :: MIT License",
		"Programming Language :: Python :: 3",
		"Programming Language :: Python :: 3.6.8",
	],
	packages = ['email_validation'],
	include_package_data = True,
	install_requires = ['urllib.request', 'socket', 'smtplib', 'dns.resolver', 'logging', 're', 'tldextract'],
	entry_points = {

	}
)
