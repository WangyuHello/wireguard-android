/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.config;

import android.util.Pair;

import com.wireguard.util.NonNullForAll;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import org.xbill.DNS.DClass;
import org.xbill.DNS.HTTPSRecord;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SVCBBase;
import org.xbill.DNS.SVCBBase.ParameterBase;
import org.xbill.DNS.SVCBBase.ParameterIpv4Hint;
import org.xbill.DNS.SVCBBase.ParameterIpv6Hint;
import org.xbill.DNS.SVCBBase.ParameterPort;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

import androidx.annotation.Nullable;


/**
 * An external endpoint (host and port) used to connect to a WireGuard {@link Peer}.
 * <p>
 * Instances of this class are externally immutable.
 */
@NonNullForAll
public final class InetEndpoint {
    private static final Pattern BARE_IPV6 = Pattern.compile("^[^\\[\\]]*:[^\\[\\]]*");
    private static final Pattern FORBIDDEN_CHARACTERS = Pattern.compile("[/?#]");

    private final String host;
    private final boolean isResolved;
    private final Object lock = new Object();
    private final int port;
    private Instant lastResolution = Instant.EPOCH;
    @Nullable private InetEndpoint resolved;

    private InetEndpoint(final String host, final boolean isResolved, final int port) {
        this.host = host;
        this.isResolved = isResolved;
        this.port = port;
    }

    public static InetEndpoint parse(final String endpoint) throws ParseException {
        if (FORBIDDEN_CHARACTERS.matcher(endpoint).find())
            throw new ParseException(InetEndpoint.class, endpoint, "Forbidden characters");
        final URI uri;
        try {
            uri = new URI("wg://" + endpoint);
        } catch (final URISyntaxException e) {
            throw new ParseException(InetEndpoint.class, endpoint, e);
        }
        if (uri.getPort() < 0 || uri.getPort() > 65535)
            throw new ParseException(InetEndpoint.class, endpoint, "Missing/invalid port number");
        try {
            InetAddresses.parse(uri.getHost());
            // Parsing ths host as a numeric address worked, so we don't need to do DNS lookups.
            return new InetEndpoint(uri.getHost(), true, uri.getPort());
        } catch (final ParseException ignored) {
            // Failed to parse the host as a numeric address, so it must be a DNS hostname/FQDN.
            return new InetEndpoint(uri.getHost(), false, uri.getPort());
        }
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof InetEndpoint))
            return false;
        final InetEndpoint other = (InetEndpoint) obj;
        return host.equals(other.host) && port == other.port;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    /**
     * Generate an {@code InetEndpoint} instance with the same port and the host resolved using DNS
     * to a numeric address. If the host is already numeric, the existing instance may be returned.
     * Because this function may perform network I/O, it must not be called from the main thread.
     *
     * @return the resolved endpoint, or {@link Optional#empty()}
     */
    public Optional<InetEndpoint> getResolved() {
        if (isResolved)
            return Optional.of(this);
        synchronized (lock) {
            //TODO(zx2c4): Implement a real timeout mechanism using DNS TTL
            if (Duration.between(lastResolution, Instant.now()).toMinutes() > 1) {
                try {
                    final var hasIpv6 = hasIPv6Available();

                    final Pair<Pair<ArrayList<Inet4Address>, ArrayList<Inet6Address>>, Integer> httpsRecord = tryGetHTTPSRecord(host);

                    if (hasIpv6 && !httpsRecord.first.second.isEmpty() && httpsRecord.second != 0) {
                        // https record has ipv6 address and port, use them
                        resolved = new InetEndpoint(httpsRecord.first.second.get(0).getHostAddress(), true, httpsRecord.second);
                    } else if (!httpsRecord.first.first.isEmpty() && httpsRecord.second != 0) {
                        // https record has ipv4 address and port, use them
                        resolved = new InetEndpoint(httpsRecord.first.first.get(0).getHostAddress(), true, httpsRecord.second);
                    } else {
                        // use regular dns
                        // Prefer v4 endpoints over v6 to work around DNS64 and IPv6 NAT issues.
                        final InetAddress[] candidates = InetAddress.getAllByName(host);
                        InetAddress address = candidates[0];
                        for (final InetAddress candidate : candidates) {
                            if (candidate instanceof Inet4Address) {
                                address = candidate;
                                break;
                            }
                        }
                        resolved = new InetEndpoint(address.getHostAddress(), true, port);
                    }
                    lastResolution = Instant.now();
                } catch (final UnknownHostException e) {
                    resolved = null;
                }
            }
            return Optional.ofNullable(resolved);
        }
    }

    public static Pair<Pair<ArrayList<Inet4Address>, ArrayList<Inet6Address>>, Integer> tryGetHTTPSRecord(final String host) {
        final ArrayList<Inet4Address> v4Addrs = new ArrayList<>();
        final ArrayList<Inet6Address> v6Addrs = new ArrayList<>();
        int p = 0;
        try {
            final Record queryRecord = Record.newRecord(Name.fromString(host+ '.'), Type.HTTPS, DClass.IN);
            final Message queryMessage = Message.newQuery(queryRecord);
            final Resolver r = new SimpleResolver("8.8.8.8");
            final Message answer = r.send(queryMessage);
            final List<Record> section = answer.getSection(Section.ANSWER);
            if(!section.isEmpty()) {
                final HTTPSRecord record = (HTTPSRecord)section.get(0);
                // https://datatracker.ietf.org/doc/rfc9460/
                final ParameterIpv4Hint ipv4Base = (ParameterIpv4Hint)record.getSvcParamValue(SVCBBase.IPV4HINT);
                if(ipv4Base != null) {
                    // may have 2 or more addresses
                    v4Addrs.addAll(ipv4Base.getAddresses());
                }
                final ParameterIpv6Hint ipv6Base = (ParameterIpv6Hint)record.getSvcParamValue(SVCBBase.IPV6HINT);
                if(ipv6Base != null) {
                    // may have 2 or more addresses
                    v6Addrs.addAll(ipv6Base.getAddresses());
                }
                final ParameterPort portBase = (ParameterPort)record.getSvcParamValue(SVCBBase.PORT);
                if(portBase != null) {
                    p = portBase.getPort();
                }
            }
        } catch (final IOException ignored) {

        }
        return new Pair<>(new Pair<>(v4Addrs, v6Addrs), p);
    }

    private static boolean hasIPv6Available() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                if (!networkInterface.isLoopback() && networkInterface.isUp()) {
                    Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
                    while (addresses.hasMoreElements()) {
                        InetAddress addr = addresses.nextElement();
                        if (addr instanceof Inet6Address) {
                            Inet6Address ipv6Addr = (Inet6Address) addr;
                            // Exclude link-local, site-local, and loopback addresses
                            if (!ipv6Addr.isLinkLocalAddress() && !ipv6Addr.isSiteLocalAddress() && !ipv6Addr.isLoopbackAddress()) {
                                return true; // Found a global IPv6 address
                            }
                        }
                    }
                }
            }
        } catch (final SocketException e) {
            e.printStackTrace();
        }
        return false; // No global IPv6 address found
    }

    @Override
    public int hashCode() {
        return host.hashCode() ^ port;
    }

    @Override
    public String toString() {
        final boolean isBareIpv6 = isResolved && BARE_IPV6.matcher(host).matches();
        return (isBareIpv6 ? '[' + host + ']' : host) + ':' + port;
    }
}
