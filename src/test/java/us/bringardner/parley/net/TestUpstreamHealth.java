package us.bringardner.parley.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.net.client.UpstreamHealth;
import us.bringardner.parley.net.client.UpstreamHealth.SimplePolicy;

public class TestUpstreamHealth {

	private static SimplePolicy policy() {
		return new SimplePolicy().setMinHoldOff(200).setMaxHoldOff(1000).setMaxTries(2)
				.setProbeInterval(100).setQueryTimeout(500).setMinQueryTimeout(50);
	}

	@Test
	public void holdOffDoublesUpToTheMaximum() {
		SimplePolicy p = new SimplePolicy().setMinHoldOff(5_000).setMaxHoldOff(600_000);
		assertEquals(5_000, UpstreamHealth.holdOff(p, 1));
		assertEquals(10_000, UpstreamHealth.holdOff(p, 2));
		assertEquals(320_000, UpstreamHealth.holdOff(p, 7));
		assertEquals(600_000, UpstreamHealth.holdOff(p, 8));
		assertEquals(600_000, UpstreamHealth.holdOff(p, 1000), "no overflow");
		assertEquals(1, UpstreamHealth.holdOff(new SimplePolicy().setMinHoldOff(0), 1), "at least 1");
	}

	@Test
	public void failuresPastMaxTriesHoldTheServerOff() throws Exception {
		UpstreamHealth h = new UpstreamHealth(policy());
		for(int i=0; i < 2; i++ ) {
			h.failed(h.started());
			assertTrue(h.isActive(), "within maxTries");
		}
		h.failed(h.started());
		assertFalse(h.isActive());
		assertTrue(h.getInactiveUntil() > System.currentTimeMillis());
		assertEquals(3, h.getConsecutiveFailures());
		assertTrue(h.tryProbe(), "one probe");
		assertFalse(h.tryProbe(), "not two in a row");
		Thread.sleep(120);
		assertTrue(h.tryProbe(), "another after the interval");
		h.succeeded(h.started());
		assertTrue(h.isActive(), "any answer ends the hold-off");
		assertEquals(0, h.getConsecutiveFailures());
		h.failed();
		assertEquals(1, h.getConsecutiveFailures());
	}

	@Test
	public void timeoutsFollowTheResponseTime() throws Exception {
		UpstreamHealth h = new UpstreamHealth(policy());
		assertEquals(500, h.timeoutFor(10_000), "query timeout until measured");
		assertEquals(30, h.timeoutFor(30), "never past what is left");
		assertEquals(1, h.timeoutFor(0));
		long start = h.started();
		Thread.sleep(20);
		h.succeeded(start);
		assertTrue(h.getSrtt() >= 20);
		int t = h.timeoutFor(10_000);
		assertTrue(t >= 50 && t < 500, "about twice the response time: "+t);
		h.failed(h.started());
		assertTrue(h.getSrtt() > 100, "a failure counts as slow");
		assertEquals(2, h.getSent());
		assertEquals(1, h.getAnswered());
		assertTrue(h.getAverageResponseTime() >= 10);
		assertTrue(h.getLastRequest() > 0);
		assertEquals(0, new UpstreamHealth(policy()).getAverageResponseTime());
		assertTrue(h.toString().contains("srtt="));
	}

	@Test
	public void setActive() {
		UpstreamHealth h = new UpstreamHealth(policy());
		h.setActive(false);
		assertFalse(h.isActive());
		assertTrue(h.toString().contains("held off"));
		h.setActive(true);
		assertTrue(h.isActive());
		assertThrows(IllegalArgumentException.class, () -> new UpstreamHealth(null));
		assertSame(SimplePolicy.class, h.getPolicy().getClass());
		SimplePolicy d = new SimplePolicy();
		assertEquals(5_000, d.minHoldOff());
		assertEquals(600_000, d.maxHoldOff());
		assertEquals(2, d.maxTries());
		assertEquals(1_000, d.probeInterval());
		assertEquals(2_000, d.queryTimeout());
		assertEquals(300, d.minQueryTimeout());
	}

	@Test
	public void orderPutsUnmeasuredThenFastestFirst() throws Exception {
		UpstreamHealth slow = new UpstreamHealth(policy());
		UpstreamHealth fast = new UpstreamHealth(policy());
		UpstreamHealth fresh = new UpstreamHealth(policy());
		long s = slow.started();
		Thread.sleep(30);
		slow.succeeded(s);
		fast.succeeded(fast.started());
		List<UpstreamHealth> all = Arrays.asList(slow, fast, fresh);
		assertEquals(Arrays.asList(fresh, fast, slow), UpstreamHealth.order(all, x -> x, 0));
		assertEquals(Collections.singletonList(slow), UpstreamHealth.order(Collections.singletonList(slow), x -> x, 5));
		//  equal ones rotate
		UpstreamHealth a = new UpstreamHealth(policy());
		UpstreamHealth b = new UpstreamHealth(policy());
		assertEquals(a, UpstreamHealth.order(Arrays.asList(a, b), x -> x, 0).get(0));
		assertEquals(b, UpstreamHealth.order(Arrays.asList(a, b), x -> x, 1).get(0));
	}

	@Test
	public void soonestIsTheFirstBack() {
		UpstreamHealth a = new UpstreamHealth(policy());
		UpstreamHealth b = new UpstreamHealth(policy());
		a.setActive(false);
		for(int i=0; i < 3; i++ ) {
			b.failed();
		}
		assertSame(b, UpstreamHealth.soonest(Arrays.asList(a, b), x -> x));
		assertNull(UpstreamHealth.soonest(Collections.<UpstreamHealth>emptyList(), x -> x));
	}
}
