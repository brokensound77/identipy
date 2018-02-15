#!/usr/bin/env python

import socket
import argparse
from threading import Thread


parser = argparse.ArgumentParser()
parser.add_argument('host', help='host to scan')
parser.add_argument('query_port', help='port which the scan will query for connections (ex: 22)')
parser.add_argument('-p', '--port', default='113', type=int, help='port to scan (default: 113)')
args = parser.parse_args()


def scan_port_group(host, port, query_port, range_hundreds):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    this_range = range_hundreds * 1000

    not_error = []
    failures = []
    for i in xrange(this_range, this_range + 999):
        try:
            client.send(str(i) + ', ' + query_port + '\x0d\x0a')
            results = str(client.recv(4096))
        except Exception:
            failures.append(i)
            continue
        if 'ERROR' not in results:
            not_error.append(results.strip())
    master_results.append(not_error)
    master_errors.append(failures)
    print '[+] scanned range: {0}-{1}'.format(this_range, this_range + 999)


def scan_bottom(host, port, query_port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    not_error = []
    failures = []
    for i in xrange(1, 999):
        try:
            client.send(str(i) + ', ' + query_port + '\x0d\x0a')
            results = str(client.recv(4096))
        except Exception:
            failures.append(i)
            continue
        if 'ERROR' not in results:
            not_error.append(results.strip())
    master_results.append(not_error)
    master_errors.append(failures)
    print '[+] scanned range: {0}-{1}'.format(1, 999)


def scan_top(host, port, query_port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    not_error = []
    failures = []
    for i in xrange(65000, 65536):
        try:
            client.send(str(i) + ', ' + query_port + '\x0d\x0a')
            results = str(client.recv(4096))
        except Exception:
            failures.append(i)
            continue
        if 'ERROR' not in results:
            not_error.append(results.strip())
    master_results.append(not_error)
    master_errors.append(failures)
    print '[+] scanned range: {0}-{1}'.format(65000, 65535)


def do_threaded_work(host, port, query_port):
    threads = []
    # 1 - 999
    t1 = Thread(target=scan_bottom, args=(host, port, query_port))
    t1.start()

    # 1000 - 64999
    for i in xrange(1, 65):
        t = Thread(target=scan_port_group, args=(host, port, query_port, i))
        threads.append(t)
        t.start()

    # 65000 - 65535
    t2 = Thread(target=scan_bottom, args=(host, port, query_port))
    t2.start()

    t1.join()
    for thread in threads:
        thread.join()
    t2.join()


if __name__ == '__main__':
    print '[+] starting scan on {0} {1} for connections to {2}'.format(args.host, args.port, args.query_port)
    master_results = []
    master_errors = []
    do_threaded_work(args.host, args.port, args.query_port)
    print '***********'
    print '* RESULTS *'
    print '***********'
    print
    for each_list in master_results:
        for each_result in each_list:
            print '\t- {0}'.format(each_result)

    print '**************************'
    print '* ERRORS SCANNING PORTS: *'
    print '**************************'
    print
    for each_list in master_results:
        for each_result in each_list:
            print '\t- {0}, '.format(each_result),