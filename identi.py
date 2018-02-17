#!/usr/bin/env python

# zeroex00.com
# rfc1413

import socket
import argparse
from threading import Thread


parser = argparse.ArgumentParser()
parser.add_argument('host', help='host to scan')
parser.add_argument('-q', '--query-port', nargs='+', help='port(s) which the scan will query(ex: 22 or 21 22 23)')
parser.add_argument('-p', '--port', default='113', type=int, help='port IDENT service is listening on (default: 113)')
parser.add_argument('-a', '--all-ports', action='store_true', help='queries ALL ports!')
parser.add_argument('-v', '--verbose', action='count', default=0,
                    help='increase verbosity - v: shows full success responses; vv: shows all open port responses')
args = parser.parse_args()


def clean_host(host):
    if host.startswith('http://'):
        tmp_host = host[7:]
    elif host.startswith('https://'):
        tmp_host = host[8:]
    else:
        tmp_host = host
    return tmp_host


def resolve_host(host):
    try:
        ip = socket.gethostbyname(host)
    except socket.error:
        return '?.?.?.?'
    return ip


def check_ident_port(host, port, ip):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect((host, port))
    except socket.error:
        print '[!] {0} ({1}) is not listening on port: {2}'.format(host, ip, port)
        return False
    except OverflowError:
        print '[!] Invalid port!: {0}'.format(port)
        return False
    client.close()
    return True


def enum_port(host, port, query_port, verbose=0):
    try:
        client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client1.connect((host, query_port))
        local_port = client1.getsockname()[1]
    except socket.error:
        master_errors.append('{0:>5}: connection refused'.format(query_port))
        return
    except OverflowError:
        master_errors.append('{0:>5}: invalid port'.format(query_port))
        return
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    try:
        client.send(str(query_port) + ',' + str(local_port) + '\x0d\x0a')
        results = str(client.recv(4096))
        client1.settimeout(1)
        client1.send('\x0d\x0a')
        try:
            banner = str(client1.recv(4096)).strip()
        except socket.error:
            banner = ''
    except Exception as e:
        master_errors.append('{0:>5}: e'.format(query_port, e))
        client1.close()
        client.close()
        return
    if verbose > 1:
        master_results.append(results.strip())
        master_banners[str(query_port)] = str(banner)
    elif ': USERID :' in results:
        master_results.append(results.strip())
        master_banners[str(query_port)] = str(banner)
    client1.close()
    client.close()


def do_threaded_work(host, port, q_ports, verbose=0):
    threads = []
    for i in q_ports:
        t = Thread(target=enum_port, args=(host, port, int(i), verbose))
        threads.append(t)
        t.start()
    for thread in threads:
        thread.join()


def print_results(suppress=False, verbose=0):
    print '[*] Results:'
    if verbose > 0:
        print '\tRaw responses || Banners'
    elif verbose == 0:
        print '\t{:>5}  {1:<20} {2}'.format('Port', 'Username', 'Banner')
        print '\t{:>5}  {1:<20} {2}'.format('----', '--------', '------')
    for each_result in master_results:
        tmp_result = each_result.split(':')  # ports, USERID, UNIX, username
        result_port = str(tmp_result[0].split(',')[0]).strip()
        result_username = tmp_result[3]
        result_banner = master_banners.get(result_port, '')
        if verbose > 0:
            print '\t{0} || {1}'.format(each_result, result_banner)
        else:
            print '\t{0:>5}: {1:<20} {2}'.format(result_port, result_username, result_banner)

    if suppress:
        return
    print '[!] Errors:'
    for each_result in master_errors:
        print '\t{0}'.format(each_result)
    if len(master_results) == 0 and len(master_errors) == 0:
        print ('[+] A lack of results AND errors could mean that the specified IDENT port is not actually running the '
               'IDENT service')


if __name__ == '__main__':
    if args.query_port is not None and len(args.query_port) == 0 and not args.all_ports:
        print '[!] you must specify at least one port or -a'
        exit(2)
    hostname = clean_host(args.host)
    ip_addr = resolve_host(hostname)
    if not check_ident_port(args.host, args.port, ip_addr):
        print '[!] Exiting...'
        exit(1)
    master_results = []
    master_banners = {}
    master_errors = []
    if args.all_ports:
        query_ports = map(lambda x: str(x), range(1, 65536))
        q_string = '1-65535'
    else:
        query_ports = args.query_port
        q_string = ' '.join(query_ports)
    print '[+] starting scan on {0} ({1}) {2} for connections to {3}'.format(hostname, ip_addr, args.port, q_string)
    try:
        do_threaded_work(args.host, args.port, query_ports, verbose=args.verbose)
    except KeyboardInterrupt:
        print 'Interrupted! Printing results:'
        print_results(suppress=True, verbose=args.verbose)
        print '[!] Errors suppressed on interrupt!'
        exit(1)
    if args.all_ports:
        print_results(suppress=True, verbose=args.verbose)
        print'[!] Errors suppressed on full scan!'
    else:
        print_results(verbose=args.verbose)
    exit(0)
