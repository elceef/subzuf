from setuptools import setup

def get_version(rel_path):
	with open(rel_path) as f:
		for line in f.read().splitlines():
			if line.startswith('__version__'):
				delim = '"' if '"' in line else "'"
				return line.split(delim)[1]
	raise RuntimeError('Unable to find version string')

setup(
	name='subzuf',
	version=get_version('subzuf.py'),
	author='Marcin Ulikowski',
	author_email='marcin@ulikowski.pl',
	description='Smart subdomain fuzzer coupled with DNS response-guided algorithm',
	long_description='Project website: https://github.com/elceef/subzuf',
	url='https://github.com/elceef/subzuf',
	license='ASL 2.0',
	py_modules=['subzuf'],
	entry_points={
		'console_scripts': ['subzuf=subzuf:run']
	},
	install_requires=[],
	classifiers=[
		'Programming Language :: Python :: 3',
		'License :: OSI Approved :: Apache Software License',
		'Operating System :: OS Independent',
	],
)
