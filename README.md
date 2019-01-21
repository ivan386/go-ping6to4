Options:
```bash
  -my_ipv4 string
        your public ipv4 address (example "192.0.2.0")
  -ping_ipv6 string
        ipv6 host to ping (example "2001:db8::")
  -tunnel string
        6to4 tunnel ipv4 address (default "192.88.99.1")
```

Example:
```bash
ping6to4 -my_ipv4 192.0.2.0 -ping_ipv6 2001:db8::
Ping from
  IPv4: 192.0.2.0
  IPv6: 2002:c000:200:5684::1
To
  IPv4(tunnel): 192.88.99.1
  IPv6: 2001:db8::
6to4 send ping: 2002:c000:200:5684::1 (sender) -> 192.88.99.1 (tunnel) -> 2001:db8:: (host)

6to4 responce tunnel: 192.88.99.1
6to4 responce from: 2001:db8::
6to4 responce to: 2002:c000:200:5684::1
6to4 responce type: EchoReply (true)
6to4 responce seq: 41687 (true)

Ok
```