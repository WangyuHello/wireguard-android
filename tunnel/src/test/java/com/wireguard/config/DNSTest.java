/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.config;

import org.junit.Test;

public class DNSTest {
    @Test
    public void lookup() {
        InetEndpoint.tryGetHTTPSRecord("google.com");
    }
}
