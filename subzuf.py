#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r'''
           _               __ 
 ___ _   _| |__ _____   _ / _|
/ __| | | | '_ \_  / | | | |_ 
\__ \ |_| | |_) / /| |_| |  _|
|___/\__,_|_.__/___|\__,_|_|  

        smart subdomain fuzzer

Created by Marcin Ulikowski <marcin@ulikowski.pl>


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''


__author__ = 'Marcin Ulikowski'
__email__ = 'marcin@ulikowski.pl'
__version__ = '2023.1.0'


import sys
import os
import re
import signal
import time
import socket
import itertools
import getopt
import concurrent.futures


THREADS = min(32, os.cpu_count() + 4)
RESOLVERS = ('1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4')
LOOP_MAX = 9
IPADDR_REGEX = re.compile(r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$')
HOSTNAME_REGEX = re.compile(r'^(?:(?:[a-z0-9_]{1,63}|[a-z0-9_][a-z0-9\-]{0,61}[a-z0-9])\.)*(?:[a-z0-9_]{1,63}|[a-z0-9_][a-z0-9\-]{0,61}[a-z0-9])$',
	re.IGNORECASE)

if sys.platform != 'win32' and sys.stdout.isatty():
	cYEL = '\x1b[33m'
	cCYA = '\x1b[36m'
	cBLU = '\x1b[34m'
	cGRN = '\x1b[32m'
	cRST = '\x1b[39m'
	sBRI = '\x1b[1m'
	sRST = '\x1b[0m'
	sCLR = '\x1b[1K'
else:
	cYEL = cCYA = cBLU = cGRN = cRST = sBRI = sRST = sCLR = ''


class DNS(dict):
	'''Simplified and flattened DNS response object'''

	def __getattr__(self, item):
		if item in self:
			return self[item]
		return None

	__setattr__ = dict.__setitem__

	def __init__(self, domain=''):
		super(dict, self).__init__()
		self.domain = domain
		self.servfail = False
		self.refused = False
		self.a = []
		self.cname = []
		self.ns = []
		self._ptr = []

	def __hash__(self):
		return hash(self.domain)

	def __eq__(self, other):
		return self.domain == other.domain

	def __lt__(self, other):
		return self.domain < other.domain


class DNSException(Exception):
	'''Generic DNS Exception'''

class NXDOMAIN(DNSException):
	'''Failed because the domain name does not exist'''

class SERVFAIL(DNSException):
	'''Failed because an answer cannot be given'''

class REFUSED(DNSException):
	'''Failed because the server refused to answer due to policy'''


class BuffReader():
	def __init__(self, buf):
		self.buf = buf
		self.p = 0

	def read(self, n=0):
		self.p += n
		return self.buf[self.p-n: self.p]

	def skip(self, n=0):
		self.p += n


class QResolver():
	'''
	Bare minimum and performance optimized DNS resolver.
	Sends EDNS0 option setting 1232 bytes of payload.
	'''

	RDTYPE_A = 0x0001
	RDTYPE_NS = 0x0002
	RDTYPE_CNAME = 0x0005
	RDTYPE_PTR = 0x000c
	RCODE_SERVFAIL = 0x2
	RCODE_NXDOMAIN = 0x3
	RCODE_REFUSED = 0x5
	SOCKET_TIMEOUT = 3

	@staticmethod
	def _build_query(fqdn, rdtype=RDTYPE_A):
		qname = b''.join([len(x).to_bytes(1, 'big') + x for x in fqdn.encode('idna').split(b'.')])
		return b''.join([b'\x19\x86\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01',
			qname,
			b'\x00',
			rdtype.to_bytes(2, 'big'),
			b'\x00\x01\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00',
			])

	@classmethod
	def _decompress_name(cls, data, packet):
		labels = []
		i = 0

		while i < len(data):
			b = data[i]

			if not b:
				break

			if b & 0xc0:
				pointer = ((b & 0x3f) << 8) + data[i+1]
				nul = packet.find(b'\x00', pointer, pointer+253)
				d = packet[pointer: nul]
				label = cls._decompress_name(d, packet)
				labels.append(label)
				break
			else:
				label = data[i+1: i+1+b]
				labels.append(label.decode('idna'))
				i += b

			i += 1

		return '.'.join(labels)

	@classmethod
	def _parse_response(cls, response, qname):
		to_int = lambda b: int.from_bytes(b, 'big')

		reader = BuffReader(response)

		header = reader.read(12)

		rn = []
		while True:
			rl = reader.read(1)[0]
			if rl:
				rn.append(reader.read(rl))
			else:
				reader.skip(4)
				break

		rname = b'.'.join(rn).decode('idna')
		if qname != rname:
			raise DNSException('Inconsistent DNS query and response: {} <> {}'.format(qname, rname))

		flags = to_int(header[2:4])
		rcode = flags & 0x0003

		answer_rr = to_int(header[6:8])

		if rcode == cls.RCODE_NXDOMAIN:
			# ignore NXDOMAIN if answer is present
			if answer_rr == 0:
				raise NXDOMAIN('Domain name does not exist: {}'.format(qname))

		elif rcode == cls.RCODE_SERVFAIL:
			raise SERVFAIL('Server failed to complete request: {}'.format(qname))

		elif rcode == cls.RCODE_REFUSED:
			raise REFUSED('Server refused to answer: {}'.format(qname))

		elif rcode > 0:
			raise DNSException('DNS resolution error code: 0x{:x}'.format(rcode))

		rr = {}

		rdtype_name = {
			cls.RDTYPE_A: 'a',
			cls.RDTYPE_NS: 'ns',
			cls.RDTYPE_CNAME: 'cname',
			cls.RDTYPE_PTR: 'ptr',
			}

		for _ in range(answer_rr):
			reader.skip(2)
			type_id = to_int(reader.read(2))
			type_name = rdtype_name.get(type_id, 'type_{}'.format(type_id))

			reader.skip(6)
			dlen = reader.read(2)
			data = reader.read(to_int(dlen))

			if type_id == cls.RDTYPE_A:
				item = socket._socket.inet_ntoa(data)

			elif type_id in (cls.RDTYPE_CNAME, cls.RDTYPE_NS, cls.RDTYPE_PTR):
				item = cls._decompress_name(data, response)

			else:
				continue

			rr.setdefault(type_name, []).append(item)

		return rr

	@classmethod
	def resolve(cls, resolver, fqdn, rdtype=RDTYPE_A, timeout=SOCKET_TIMEOUT):
		query = cls._build_query(fqdn, rdtype)

		sock = socket._socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.settimeout(timeout)

		try:
			sock.sendto(query, (resolver, 53))
			resp = sock.recv(1232)
		except Exception as e:
			raise
		else:
			return cls._parse_response(resp, fqdn)
		finally:
			sock.close()


def nslookup(resolver, fqdn):
	dns = DNS(fqdn)

	try:
		res = QResolver.resolve(resolver, fqdn, rdtype=QResolver.RDTYPE_A)
	except NXDOMAIN:
		raise
	except SERVFAIL:
		dns.servfail = True
		return dns
	except REFUSED:
		dns.refused = True
		return dns
	except Exception:
		raise
	else:
		dns.a = sorted(res.get('a', []))
		dns.cname = res.get('cname', [])

	try:
		res = QResolver.resolve(resolver, fqdn, rdtype=QResolver.RDTYPE_NS)
	except (NXDOMAIN, SERVFAIL, REFUSED):
		pass
	except Exception:
		pass
	else:
		dns.ns = res.get('ns', [])

	for ipaddr in set(dns.a):
		inaddr_arpa = '.'.join(ipaddr.split('.')[::-1]) + '.in-addr.arpa'
		try:
			res = QResolver.resolve(resolver, inaddr_arpa, rdtype=QResolver.RDTYPE_PTR)
		except (NXDOMAIN, SERVFAIL, REFUSED):
			pass
		except Exception:
			pass
		else:
			dns._ptr += res.get('ptr', [])

	return dns


class Fuzzer():
	swaps = (('dev', 'stg', 'stage', 'test', 'qa', 'uat', 'preprod'),
		#('staging', 'testing', 'development'),
		('in', 'out'),
		('inbound', 'outbound'),
		('ext', 'int'),
		('extern', 'intern'),
		('external', 'internal'),
		('local', 'global'),
		('east', 'west'),
		('private', 'public'),
		('priv', 'pub'),
		('ap', 'eu', 'na', 'la', 'ca'),
		('nam', 'emea', 'apac', 'latam'),
		('en', 'de', 'fr', 'jp', 'uk'),
		('a', 'b', 'c'),
		('1a', '1b', '1c'),
		('2a', '2b', '2c'),
		)
	def __init__(self, domain='.'):
		self.subdomains = set()
		self.domain = domain

	def _fuzz(self, word):
		swaps = self.swaps
		words = list(filter(None, word.split('-')))
		for i in range(1, len(words)):
			yield '-'.join(words[:i])
		for i, w in enumerate(words):
			pre = words[:i]
			suf = words[i+1:]
			if w[-1].isdigit():
				n = ord(w[-1])
				for d in map(chr, range(n, min(0x3a, n+5))):
					yield '-'.join(pre + [w[:-1] + d] + suf)
			for swap in swaps:
				if w in swap:
					for s in swap:
						yield '-'.join(pre + [s] + suf)

	def _prep(self, string):
		labels = string.split('.')
		for i, label in enumerate(labels):
			pre = labels[:i]
			suf = labels[i+1:]
			self.subdomains.add('.'.join(labels[i:]))
			for f in self._fuzz(label):
				self.subdomains.add('.'.join(pre + [f] + suf))

	def add(self, items):
		if not isinstance(items, (list,set)):
			raise ValueError('expected argument types: list, set')
		dotlen = len(self.domain) + 1
		for item in filter(None, items):
			if dotlen < len(item):
				if item[-dotlen] == '.':
					if item.endswith(self.domain):
						self._prep(item[:-dotlen])
				else:
					self._prep(item)
			else:
				self._prep(item)

	def mutations(self):
		for sub in self.subdomains:
			yield '.'.join([sub, self.domain])

	def wildations(self):
		for wild in {'.'.join(['*'] + sub.split('.', 1)[1:]) for sub in self.subdomains}:
			yield wild + '.' + self.domain

	def count(self):
		return len(self.subdomains)


def chunkify(iterable, chunk=1000):
    it = iter(iterable)
    while True:
        piece = list(itertools.islice(it, chunk))
        if piece:
            yield piece
        else:
            return


def to_wild(domain):
	return '.'.join(['*', domain.partition('.')[2]])


def status(message):
	if sys.stdout.isatty(): print(sCLR + '\r' + message, end='', flush=True)

def fatal(message):
	print('error: {}'.format(message), file=sys.stderr, flush=True)
	sys.exit(2)


help_screen = '''usage: {} [option]... domain

smart subdomain fuzzer coupled with DNS reponse-guided algorithm

required arguments:

  domain              target domain name

optional arguments:

  --input file        input file with test cases (default: stdin)
  --output file       output file for findings
  --format type       output format type: cli, json, list
  --resolvers file    ingest DNS resolvers from text file
  --threads number    run specified number of worker threads
  --wildcard mode     wildcard detection mode: filter (default), reject, off

examples:

  $ subzuf --in wordlist.txt example.com
  $ ./scripts/crt.sh example.com | subzuf example.com
'''.format(sys.argv[0])


def run():
	if sys.stdout.isatty():
		print('{}subzuf {} by <{}>{}\n'.format(sBRI, __version__, __email__, sRST))

	if not sys.argv[1:] or '--help' in sys.argv or '-h' in sys.argv:
		print(help_screen)
		return

	try:
		opts, domain = getopt.gnu_getopt(sys.argv[1:], '',
			['input=', 'output=', 'format=', 'resolvers=', 'threads=', 'wildcard='])
	except getopt.GetoptError as err:
		fatal(err)

	class args:
		domain = None
		input = sys.stdin
		output = None
		format = None
		resolvers = None
		threads = THREADS
		wildcard = 'filter'

	if not domain:
		fatal('domain name is required')
	args.domain = domain[0]

	for opt, val in opts:
		if opt == '--input':
			if val != '-':
				try:
					args.input = open(val, 'r', encoding='utf-8')
				except OSError as err:
					fatal('unable to open {} ({})'.format(val, err.strerror.lower()))

		elif opt == '--output':
			if os.path.exists(val):
				fatal('{} already exists'.format(val))
			try:
				args.output = open(val, 'w', encoding='utf-8')
			except OSError as err:
				fatal('unable to open {} ({})'.format(val, err.strerror.lower()))

		elif opt == '--format':
			if val in ('cli', 'list', 'json'):
				args.format = val
			else:
				fatal('output format not recognized')

		elif opt == '--resolvers':
			try:
				args.resolvers = open(val, 'r')
			except OSError as err:
				fatal(err)

		elif opt == '--threads':
			try:
				args.threads = int(val)
			except ValueError:
				fatal('number of threads must be a positive integer')
			else:
				if args.threads < 1:
					fatal('number of threads must be positive')
				if args.threads > 10**3:
					fatal('number of threads is dangerously high')

		elif opt == '--wildcard':
			if val in ('filter', 'reject', 'off'):
				args.wildcard = val
			else:
				fatal('wildcard detection mode not recognized')

	executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.threads)

	def signal_handler(signal, frame):
		status('stopping...\n')
		executor.shutdown(wait=False)
		while True:
			try:
				work_item = executor._work_queue.get_nowait()
			except Exception:
				break
			else:
				if work_item:
					work_item.future.cancel()
		sys.tracebacklimit = 0
		raise KeyboardInterrupt

	for sig in (signal.SIGINT, signal.SIGTERM):
		signal.signal(sig, signal_handler)

	# test DNS resolvers

	resolvers = RESOLVERS
	if args.resolvers:
		with args.resolvers as f:
			try:
				resolvers = [resolv for resolv in f.read().splitlines()
					if IPADDR_REGEX.match(resolv)]
			except UnicodeDecodeError:
				fatal('unable to parse {}'.format(f.name))

		randnx = 'subzuf-{:x}.com'.format(int.from_bytes(os.urandom(8), 'little'))

		futures = {executor.submit(QResolver.resolve, resolver=resolv, fqdn=randnx, timeout=1): resolv
			for resolv in resolvers}

		for future in concurrent.futures.as_completed(futures):
			try:
				res = future.result()
			except NXDOMAIN:
				futures.pop(future)
				continue
			except Exception:
				pass

			resolv = futures.pop(future)
			resolvers.remove(resolv)
			status('rejected resolver: {}\n'.format(resolv))

	if not resolvers:
		fatal('all DNS resolvers have been rejected')
	iresolver = itertools.cycle(resolvers)

	# read input data

	status('reading input from: {}'.format(args.input.name))

	with args.input as f:
		try:
			words = [word.strip('*.- ').lower() for word in f.read().splitlines()
				if HOSTNAME_REGEX.match(word.strip('*.- '))]
		except UnicodeDecodeError:
			fatal('invalid input')

	# all checks complete, input cases ready, start main loop

	subdomains = set()
	wildcards = dict()
	errors = 0

	s_perf = time.perf_counter()

	loopn = 0
	while True:
		loopn += 1

		status('fuzzing...')

		fuzz = Fuzzer(args.domain)
		fuzz.add(words)

		if args.wildcard in ('filter', 'reject'):

			for wbucket in chunkify(fuzz.wildations(), args.threads*100):
				futures = {executor.submit(nslookup, resolver=next(iresolver), fqdn=wtest): wtest
					for wtest in wbucket if wtest not in wildcards}
	
				for future in concurrent.futures.as_completed(futures):
					try:
						wtest = future.result()
					except Exception:
						pass
					else:
						if not (wtest.servfail or wtest.refused):
							status('wildcard found: {}\n'.format(wtest.domain))
							wildcards[wtest.domain] = wtest.a
					finally:
						domain = futures.pop(future)

					status('wildcards: {} | testing: {}'.format(len(wildcards), domain))

		status('scanning...')

		done = 0

		f_cnt = fuzz.count()
		p_perf = time.perf_counter()

		exist = set()

		for bucket in chunkify(fuzz.mutations(), args.threads*100):

			futures = dict()

			for elem in bucket:
				if args.wildcard == 'reject':
					if any([wild_cmp(elem, wild) for wild in wildcards]):
						done += 1
						continue

				future = executor.submit(nslookup, resolver=next(iresolver), fqdn=elem)
				futures[future] = elem

			for future in concurrent.futures.as_completed(futures):
				try:
					res = future.result()
				except NXDOMAIN:
					pass
				except Exception:
					errors += 1
				else:
					if args.wildcard == 'filter' and not (res.servfail or res.refused):
						if wildcards.get(to_wild(res.domain)) != res.a:
							exist.add(res)
					else:
						exist.add(res)
				finally:
					futures.pop(future)
					done += 1

				if done > args.threads and done % args.threads:
					continue

				rate = int(done / (time.perf_counter() - p_perf)) + 1
				eta = int((f_cnt - done) / rate)

				status(' | '.join([
					'loop: #{}'.format(loopn),
					'progress: {}{:.2%}{}'.format(sBRI, done / f_cnt, sRST),
					'found: {}{}{}/{}'.format(sBRI, len(exist), sRST, f_cnt),
					'errors: {} ({:.2%})'.format(errors, errors / done),
					'speed: {}/s'.format(rate),
					'eta: {:d}h {:02d}m {:02d}s'.format(eta // 3600, eta % 3600 // 60, eta % 3600 % 60),])
					)

		subdomains |= exist

		if loopn >= LOOP_MAX:
			# this probably never happens
			break

		extras = set()

		for item in exist:
			for i in item.cname + item.ns + item._ptr:
				if i.endswith('.' + args.domain):
					extras.add(i)

		extras -= {x.domain for x in subdomains}

		if extras:
			for mut in fuzz.mutations():
				extras.discard(mut)

		if extras:
			words = extras
		else:
			break

	# display summary and results

	results = sorted(subdomains)

	ttime = int(time.perf_counter() - s_perf)

	status(' | '.join([
		'complete',
		'found: {}{}{}'.format(sBRI, len(results), sRST),
		'errors: {}{}{}'.format(sBRI, errors, sRST),
		'time: {:d}h {:02d}m {:02d}s'.format(ttime // 3600, ttime % 3600 // 60, ttime % 3600 % 60),])
		+ '\n\n'
		)

	if not results:
		return

	if args.output:
		sys.stdout = args.output

	if args.format == 'json' or not (args.format or sys.stdout.isatty()) or (not args.format and args.output):
		import json
		print(json.dumps([{k: v for k, v in res.items() if not k[0] == '_'} for res in results]))

	elif args.format == 'list':
		print('\n'.join([res.domain for res in results]))

	else:
		wdom = max([len(res.domain) for res in results]) + 1

		for res in results:
			if (res.cname and res.a):
				print('{}{:<{}} {} ({}){}'.format(sBRI+cCYA, res.domain, wdom, res.cname[-1], res.a[-1], cRST+sRST))

			elif (res.cname and not res.a):
				print('{}{:<{}} {} (?){}'.format(sBRI+cBLU, res.domain, wdom, res.cname[-1], cRST+sRST))
	
			elif (res.ns and not res.a and not res.cname):
				print('{}{:<{}} [{}]{}'.format(sBRI+cGRN, res.domain, wdom, ' '.join(res.ns[:3]), cRST+sRST))

			elif (res.ns and res.a):
				print('{}{:<{}} {} [{}]{}'.format(sBRI+cGRN, res.domain, wdom, res.a[-1], ' '.join(res.ns[:3]), cRST+sRST))

			elif (not res.cname and res.a):
				print('{:<{}} {}'.format(res.domain, wdom, res.a[-1]))

			elif (res.servfail or res.refused):
				print('{}{:<{}} SERVFAIL/REFUSED{}'.format(sBRI+cYEL, res.domain, wdom, cRST+sRST))
	
			else:
				print(res.domain)


if __name__ == '__main__':
	try:
		run()
	except BrokenPipeError:
		pass
