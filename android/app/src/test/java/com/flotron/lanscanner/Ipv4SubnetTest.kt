package com.flotron.lanscanner

import org.junit.Assert.*
import org.junit.Test

class Ipv4SubnetTest {
    @Test fun fullPrivateRangeUsesUnsignedAddresses() {
        val hosts = Ipv4Subnet.hosts("192.168.1.228", 24)
        assertEquals(254, hosts.size)
        assertEquals("192.168.1.1", hosts.first())
        assertEquals("192.168.1.254", hosts.last())
    }
    @Test fun slash23IncludesBothHalvesAndTheirInteriorEndpoints() {
        val hosts = Ipv4Subnet.hosts("192.168.0.0", 23)
        assertEquals(510, hosts.size)
        assertEquals("192.168.0.1", hosts.first())
        assertEquals("192.168.1.254", hosts.last())
        assertTrue("192.168.0.255" in hosts)
        assertTrue("192.168.1.0" in hosts)
        assertEquals(4094, Ipv4Subnet.hosts("10.0.0.0", 20).size)
    }
    @Test fun actualLanCanSpanTwoScanRanges() {
        assertTrue(Ipv4Subnet.contains("192.168.0.26", 23, "192.168.1.200"))
        assertFalse(Ipv4Subnet.contains("192.168.13.26", 24, "192.168.0.100"))
    }
    @Test fun smallerNetworkExcludesNetworkAndBroadcast() {
        assertEquals(listOf("10.0.0.5", "10.0.0.6"), Ipv4Subnet.hosts("10.0.0.6", 30))
    }
    @Test fun invalidAddressesAndLargeScansAreRejected() {
        for (ip in listOf("example.com", "192.168.1.256", "1.2.3", "-1.0.0.1", "1.2.3.+4")) {
            assertTrue(runCatching { Ipv4Subnet.value(ip) }.isFailure)
        }
        assertTrue(runCatching { Ipv4Subnet.hosts("10.0.0.1", 16) }.isFailure)
        assertTrue(runCatching { Ipv4Subnet.hosts("10.0.0.1", 32) }.isFailure)
    }
}
