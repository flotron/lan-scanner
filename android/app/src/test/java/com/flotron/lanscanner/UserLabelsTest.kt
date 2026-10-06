package com.flotron.lanscanner

import org.junit.Assert.*
import org.junit.Test

class UserLabelsTest {
    @Test fun identityIsCanonicalAndIndependentOfIp() {
        assertEquals("AA:BB:CC:11:22:33", UserLabels.macKey("aa-bb-cc-11-22-33"))
        assertNull(UserLabels.macKey("Unavailable (routed)"))
        assertNull(UserLabels.macKey("00:00:00:00:00:00"))
        assertNull(UserLabels.macKey("FF:FF:FF:FF:FF:FF"))
    }
    @Test fun groupsAcceptDifferentSubnetsAndDeduplicate() {
        assertEquals(listOf("192.168.0.2", "192.168.13.8"),
            UserLabels.addresses(listOf("192.168.0.2", "192.168.13.8", "192.168.0.2")))
    }
    @Test(expected = IllegalArgumentException::class) fun rejectsTooManyTargets() {
        UserLabels.addresses(List(17) { "192.168.0.2" })
    }
    @Test(expected = IllegalArgumentException::class) fun rejectsMalformedAddress() {
        UserLabels.addresses(listOf("192.168.0.999"))
    }
    @Test(expected = IllegalArgumentException::class) fun rejectsBlankName() { UserLabels.label("  ") }
}
