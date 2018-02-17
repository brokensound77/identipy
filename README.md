# identipy

Hopefully no one is still running IDENT services wide open, but if they are, it can be a great tool for red teams during penetration testing. For full details, go here: 

## Usage

```
usage: identi.py [-h] [-q QUERY_PORT [QUERY_PORT ...]] [-p PORT] [-a] host

positional arguments:
  host                  host to scan

optional arguments:
  -h, --help            show this help message and exit
  -q QUERY_PORT [QUERY_PORT ...], --query-port QUERY_PORT [QUERY_PORT ...] 
                        port(s) which the scan will query(ex: 22 or 21 22 23)
  -p PORT, --port PORT  port IDENT service is listening on (default: 113)
  -a, --all-ports       queries ALL ports!
  -v, --verbose        increase verbosity - v: shows full success responses;
                        vv: shows all open port responses
  ```
  
  ## Scanning 1 or more ports
  
  ```
  python identi.py 10.1.1.236 -q 22 80 139 445
  [+] starting scan on 10.1.1.236 113 for connections to 22 80 113 139 445
  [+] Results:
           Port  Username            Banner
           ----  --------            ------
             22: root                SSH-2.0-OpennSSH_4.2p1 Debian-8
            113: identd              0 , 0 : ERROR : UNKNOWN-ERROR
            139: root
            445: root
  [!] Errors:
            80: connection refused
  ```
  
  ## Scanning ALL ports
  
  ```
  python identi.py 10.1.1.236 -a
  [+] starting scan on 10.1.1.236 113 for connections to 1-65535
  [+] Results:
           Port  Username            Banner
           ----  --------            ------
             22: root                SSH-2.0-OpennSSH_4.2p1 Debian-8 
            113: identd              0 , 0 : ERROR : UNKNOWN-ERROR 
            139: root
            445: root
  [!] Errors suppressed on full scan!
  ```

## Using verbose to find hidden services

```
  python identi.py 10.1.1.236 -avv
  [+] starting scan on 10.1.1.236 113 for connections to 1-65535
  [+] Results:
          (VERBOSE:Raw responses || Banners)
           2222 , 53282 : USERID : OTHER : root || SSH-2.0-OpennSSH_4.2p1 Debian-8 
            113 , 54716 : USERID : OTHER : 99 || 0 , 0 : ERROR : UNKNOWN-ERROR
             37 , 54221 : ERROR : UNKNOWN-ERROR
          55753 , 54112 : ERROR : HIDDEN-USER 
  [!] Errors suppressed on full scan!
  ```
