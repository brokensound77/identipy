# identipy

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
  ```
  
  ## Scanning 1 or more ports
  
  ```
  python identi.py 10.1.1.236 -q 22 80 139 445
  [+] starting scan on 10.1.1.236 113 for connections to 22 80 113 139 445
  [+] Results:
             22: root 
            113: identd 
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
             22: root 
            113: identd 
            139: root
            445: root
  [!] Errors suppressed on full scan!
  ```
