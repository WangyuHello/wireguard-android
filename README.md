# Android GUI for [WireGuard](https://www.wireguard.com/)

## Add HTTPS dns record support
[What is HTTPS dns record ?](https://vercara.digicert.com/resources/svcb-and-https-dns-records-the-future-of-service-discovery-and-connection-establishment)

A HTTPS dns record can store WireGuard port, ipv4 address and ipv6 address together. We can use them for peer host resolution.

An example of HTTPS record:

```
1 . alpn="h3" port=12345 ipv4hint=xxx.xxx.xxx.xxx ipv6hint=yyyy:yyyy:yyyy:yyyy::y
```

This modified WireGuard client will choose ipv6 address if the phone has a unicast ipv6 address.

## Related project

Use [Natmap](https://github.com/heiher/natmap) for UDP hole punching and get ipv4 address and port. use this [scripts](https://github.com/heiher/natmap/issues/13#issuecomment-3236881490) to add HTTPS DNS record.