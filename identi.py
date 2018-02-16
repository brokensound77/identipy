#!/usr/bin/env python

import socket
import argparse
from threading import Thread


parser = argparse.ArgumentParser()
parser.add_argument('host', help='host to scan')
parser.add_argument('-q', '--query_port', nargs='+', help='port(s) which the scan will query(ex: 22 or 21 22 23)')
parser.add_argument('-p', '--port', default='113', type=int, help='port IDENT service is listening on (default: 113)')
parser.add_argument('-a', '--all-ports', action='store_true', help='queries ALL ports!')
args = parser.parse_args()


def enum_port(host, port, query_port):
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
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))
    except socket.error:
        print 'ident port NOT open!: {0}'.format(port)
        return
    except OverflowError:
        print 'ident port invalid!: {0}'.format(port)
        return

    try:
        client.send(str(query_port) + ',' + str(local_port) + '\x0d\x0a')
        results = str(client.recv(4096))
    except Exception as e:
        master_errors.append('{0:>5}: e'.format(query_port, e))
        client1.close()
        client.close()
        return
    if 'ERROR' not in results:
        master_results.append(results.strip())
    client1.close()
    client.close()


def do_threaded_work(host, port, query_ports):
    threads = []
    for i in query_ports:
        t = Thread(target=enum_port, args=(host, port, int(i)))
        threads.append(t)
        t.start()
    for thread in threads:
        thread.join()


def print_results(suppress=False):
    print '[*] Results:'
    for each_result in master_results:
        tmp_result = each_result.split(':')  # ports, USERID, UNIX, username
        result_port = str(tmp_result[0].split(',')[0]).strip()
        result_username = tmp_result[3]
        print '\t{0:>5}: {1}'.format(result_port, result_username)

    if suppress:
        return
    print '[!] Errors:'
    for each_result in master_errors:
        print '\t{0}'.format(each_result)


if __name__ == '__main__':
    if args.query_port is not None and len(args.query_port) == 0 and not args.all_ports:
        print '[!] you must specify at least one port or -a'
        exit(2)
    master_results = []
    master_errors = []
    if args.all_ports:
        query_ports = map(lambda x: str(x), range(1, 65536))
        q_string = '1-65535'
    else:
        query_ports = args.query_port
        q_string = ' '.join(query_ports)
    print '[+] starting scan on {0} {1} for connections to {2}'.format(args.host, args.port, q_string)
    try:
        do_threaded_work(args.host, args.port, query_ports)
    except KeyboardInterrupt:
        print 'Interrupted! Printing results:'
        print_results(suppress=True)
        print '[!] errors suppressed on interrupt!'
        exit(1)
    if args.all_ports:
        print_results(suppress=True)
        print'[!] errors suppressed on full scan!'
    else:
        print_results()
    exit(0)
