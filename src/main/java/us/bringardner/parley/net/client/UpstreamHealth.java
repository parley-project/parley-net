/**
 * <PRE>
 * 
 * Copyright 1998-2026 <A href="http://bringardner.us/tony">Tony Bringardner</A>
 * 
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       <A href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</A>
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *  </PRE>
 *   
 *   
 *	@author Tony Bringardner   
 *
 *
 */
package us.bringardner.parley.net.client;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.function.Function;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * What a client knows about one upstream server (one address of a DNS name server, an
 * SMTP relay, a mirror...): how fast it answers and whether it is failing.
 * <p>
 * <ul>
 * <li><b>Response time:</b> a smoothed average (EWMA, weight 1/8) of the answers; a
 *     failure counts as a slow answer, so failing servers sort behind working ones.
 *     {@link #timeoutFor(long)} gives a timeout of about twice that.</li>
 * <li><b>Hold-off:</b> after more than {@link Policy#maxTries()} failures in a row the
 *     server is held off for {@link Policy#minHoldOff()} ms, doubling with each further
 *     failure up to {@link Policy#maxHoldOff()}. Any answer ends the hold-off.</li>
 * <li><b>Probing:</b> when every server is held off, the one that comes back first may be
 *     tried at most once per {@link Policy#probeInterval()} ({@link #tryProbe()}), so an
 *     outage ends when the servers come back, not when the hold-off ends.</li>
 * </ul>
 * {@link #order} and {@link #soonest} pick among several servers. Thread safe.
 * <p>
 * From parley-dns, where a short network outage used to turn every root server off
 * for an hour.
 */
public class UpstreamHealth {

	/** The limits UpstreamHealth works with. */
	public interface Policy {
		/** @return the first hold-off (ms) */
		long minHoldOff();
		/** @return the longest hold-off (ms) */
		long maxHoldOff();
		/** @return failures in a row allowed before a hold-off */
		int maxTries();
		/** @return the shortest time (ms) between probes of a server that is held off */
		long probeInterval();
		/** @return the timeout (ms) before the response time is known, and the longest one */
		int queryTimeout();
		/** @return the shortest timeout (ms) */
		int minQueryTimeout();
	}

	/** A Policy with fixed (settable) values. */
	public static class SimplePolicy implements Policy {
		private volatile long minHoldOff = 5_000;
		private volatile long maxHoldOff = 10*60*1000L;
		private volatile int maxTries = 2;
		private volatile long probeInterval = 1_000;
		private volatile int queryTimeout = 2_000;
		private volatile int minQueryTimeout = 300;

		@Override public long minHoldOff() { return minHoldOff; }
		@Override public long maxHoldOff() { return maxHoldOff; }
		@Override public int maxTries() { return maxTries; }
		@Override public long probeInterval() { return probeInterval; }
		@Override public int queryTimeout() { return queryTimeout; }
		@Override public int minQueryTimeout() { return minQueryTimeout; }

		public SimplePolicy setMinHoldOff(long ms) { minHoldOff = ms; return this; }
		public SimplePolicy setMaxHoldOff(long ms) { maxHoldOff = ms; return this; }
		public SimplePolicy setMaxTries(int n) { maxTries = n; return this; }
		public SimplePolicy setProbeInterval(long ms) { probeInterval = ms; return this; }
		public SimplePolicy setQueryTimeout(int ms) { queryTimeout = ms; return this; }
		public SimplePolicy setMinQueryTimeout(int ms) { minQueryTimeout = ms; return this; }
	}

	private final Policy policy;
	private final AtomicInteger sent = new AtomicInteger();
	private final AtomicInteger answered = new AtomicInteger();
	private final AtomicLong totalResponseTime = new AtomicLong();
	private final AtomicInteger consecutiveFailures = new AtomicInteger();
	private final AtomicLong nextProbe = new AtomicLong();
	private volatile long lastRequest;
	//  Held off until this time (ms); 0: available
	private volatile long inactiveUntil;
	//  Smoothed response time (ms), 0 until the first answer
	private double srtt;

	public UpstreamHealth(Policy policy) {
		if( policy == null ) {
			throw new IllegalArgumentException("policy");
		}
		this.policy = policy;
	}

	public Policy getPolicy() {
		return policy;
	}

	// ------------------------------------------------------------------ requests

	/**
	 * A request is being sent.
	 * @return the time (ms), to pass to {@link #succeeded} or {@link #failed(long)} as the start
	 */
	public long started() {
		long now = System.currentTimeMillis();
		lastRequest = now;
		sent.incrementAndGet();
		return now;
	}

	/** The request started at start was answered: the hold-off ends. */
	public void succeeded(long start) {
		long rtt = Math.max(0, System.currentTimeMillis()-start);
		totalResponseTime.addAndGet(rtt);
		answered.incrementAndGet();
		recordRtt(Math.max(1, rtt));
		consecutiveFailures.set(0);
		inactiveUntil = 0;
	}

	/**
	 * The request started at start failed (timeout, error, a useless answer): it counts
	 * as a slow answer (twice the time it took, at least twice the query timeout), and
	 * as a failure.
	 */
	public void failed(long start) {
		long rtt = Math.max(0, System.currentTimeMillis()-start);
		totalResponseTime.addAndGet(rtt);
		recordRtt(Math.max(rtt, policy.queryTimeout())*2L);
		failed();
	}

	/**
	 * A failure without a request (e.g. the server's address is unknown); past
	 * maxTries in a row the server is held off.
	 */
	public void failed() {
		int n = consecutiveFailures.incrementAndGet();
		int max = policy.maxTries();
		if( n > max ) {
			inactiveUntil = System.currentTimeMillis()+holdOff(policy, n-max);
		}
	}

	private synchronized void recordRtt(long ms) {
		srtt = srtt == 0 ? ms : (7*srtt + ms)/8;
	}

	/**
	 * @param k failures past maxTries (1 for the first hold-off)
	 * @return minHoldOff doubled k-1 times, at most maxHoldOff (and at least 1)
	 */
	public static long holdOff(Policy policy, int k) {
		long max = policy.maxHoldOff();
		long ret = policy.minHoldOff();
		for(int i=1; i < k && ret < max; i++ ) {
			ret *= 2;
		}
		return Math.max(1, Math.min(ret, max));
	}

	// ------------------------------------------------------------------ state

	/** @return true unless the server is held off */
	public boolean isActive() {
		return System.currentTimeMillis() >= inactiveUntil;
	}

	/**
	 * May a server that is held off be tried now? True at most once per probe interval
	 * (from all threads together).
	 */
	public boolean tryProbe() {
		long now = System.currentTimeMillis();
		long next = nextProbe.get();
		return now >= next && nextProbe.compareAndSet(next, now+policy.probeInterval());
	}

	/** End the hold-off and forget the failures (true), or hold the server off for maxHoldOff (false). */
	public void setActive(boolean active) {
		if( active ) {
			consecutiveFailures.set(0);
			inactiveUntil = 0;
		} else {
			inactiveUntil = System.currentTimeMillis()+policy.maxHoldOff();
		}
	}

	/**
	 * @param remaining time left (ms) for the whole operation
	 * @return the timeout for the next request: about twice the smoothed response time
	 *  (minQueryTimeout to queryTimeout) once it is known, queryTimeout before that, never
	 *  more than remaining (and at least 1)
	 */
	public int timeoutFor(long remaining) {
		double s = getSmoothedResponseTime();
		long t = s > 0 ? Math.max(policy.minQueryTimeout(), Math.min(policy.queryTimeout(), Math.round(s*2)+100)) : policy.queryTimeout();
		return (int) Math.max(1, Math.min(t, remaining));
	}

	/** @return when the hold-off ends (ms); 0 or a past time if the server is active */
	public long getInactiveUntil() {
		return inactiveUntil;
	}

	/** @return the smoothed response time (ms), 0 if the server has never answered */
	public synchronized double getSmoothedResponseTime() {
		return srtt;
	}

	/** @return the smoothed response time rounded (ms), 0 if the server has never answered */
	public long getSrtt() {
		return Math.round(getSmoothedResponseTime());
	}

	public int getSent() {
		return sent.get();
	}

	public int getAnswered() {
		return answered.get();
	}

	public int getConsecutiveFailures() {
		return consecutiveFailures.get();
	}

	public long getLastRequest() {
		return lastRequest;
	}

	/** @return the average time (ms) of all requests sent, 0 if none */
	public int getAverageResponseTime() {
		int n = sent.get();
		return n == 0 ? 0 : (int) (totalResponseTime.get()/n);
	}

	// ------------------------------------------------------------------ choosing

	/**
	 * Servers in the order to try them: never-answered ones first (so they get measured),
	 * then fastest first. Equal ones keep a rotating order, to spread the load.
	 *
	 * @param rotation e.g. a counter incremented per call
	 */
	public static <T> List<T> order(Collection<T> servers, Function<T, UpstreamHealth> health, int rotation) {
		List<T> list = new ArrayList<T>(servers);
		int size = list.size();
		if( size > 1 ) {
			Collections.rotate(list, -Math.floorMod(rotation, size));
			//  The times are read once: other threads change them while this sorts
			java.util.IdentityHashMap<T, Long> srtt = new java.util.IdentityHashMap<T, Long>();
			for(T t : list) {
				srtt.put(t, health.apply(t).getSrtt());
			}
			//  stable sort: the rotation decides among equal response times
			list.sort(Comparator.comparingLong(srtt::get));
		}
		return list;
	}

	/** @return the server whose hold-off ends first, null if there are none */
	public static <T> T soonest(Collection<T> servers, Function<T, UpstreamHealth> health) {
		T ret = null;
		long best = Long.MAX_VALUE;
		for(T t : servers) {
			long until = health.apply(t).getInactiveUntil();
			if( ret == null || until < best ) {
				ret = t;
				best = until;
			}
		}
		return ret;
	}

	@Override
	public String toString() {
		return "UpstreamHealth[srtt="+getSrtt()+", sent="+sent+", answered="+answered+", failures="+consecutiveFailures
				+(isActive() ? "" : ", held off until "+inactiveUntil)+"]";
	}
}
