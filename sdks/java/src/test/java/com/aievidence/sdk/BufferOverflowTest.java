package com.aievidence.sdk;

/**
 * Buffer Overflow & Drop Policy Test: Verifies bounded queue capacity enforcement,
 * drop counters, and overflow handling without memory leaks or crashes.
 */
public class BufferOverflowTest {

    public static void main(String[] args) throws Exception {
        new BufferOverflowTest().runAll();
    }

    public void runAll() throws Exception {
        testDropNewestPolicy();
        testDropOldestPolicy();
        System.out.println("  [PASS] BufferOverflowTest: All tests passed.");
    }

    public void testDropNewestPolicy() {
        final int capacity = 5;
        BoundedEventQueue queue = new BoundedEventQueue(capacity, DropPolicy.DROP_NEWEST);

        // Fill capacity
        for (int i = 0; i < capacity; i++) {
            DecisionEvent ev = DecisionEvent.builder()
                    .aiSystemId("sys-1")
                    .score((double) i)
                    .correlationId("tx-" + i)
                    .build();
            boolean accepted = queue.offer(ev);
            assert accepted : "Initial events within capacity must be accepted";
        }

        assert queue.size() == capacity : "Queue should be full";
        assert queue.getEnqueuedCount() == capacity : "Enqueued count should equal capacity";
        assert queue.getDroppedCount() == 0 : "Dropped count should be 0";

        // Push 10 excess events
        for (int i = capacity; i < capacity + 10; i++) {
            DecisionEvent ev = DecisionEvent.builder()
                    .aiSystemId("sys-1")
                    .score((double) i)
                    .correlationId("tx-" + i)
                    .build();
            boolean accepted = queue.offer(ev);
            assert !accepted : "Excess events under DROP_NEWEST must be rejected";
        }

        assert queue.size() == capacity : "Queue size must remain bounded at capacity";
        assert queue.getEnqueuedCount() == capacity : "Enqueued count must remain at capacity";
        assert queue.getDroppedCount() == 10 : "Dropped count must accurately record 10 dropped events, got: " + queue.getDroppedCount();
    }

    public void testDropOldestPolicy() {
        final int capacity = 5;
        BoundedEventQueue queue = new BoundedEventQueue(capacity, DropPolicy.DROP_OLDEST);

        // Fill capacity
        for (int i = 0; i < capacity; i++) {
            DecisionEvent ev = DecisionEvent.builder()
                    .aiSystemId("sys-1")
                    .score((double) i)
                    .correlationId("tx-" + i)
                    .build();
            queue.offer(ev);
        }

        assert queue.size() == capacity : "Queue should be full";

        // Push 3 new events
        for (int i = 0; i < 3; i++) {
            DecisionEvent ev = DecisionEvent.builder()
                    .aiSystemId("sys-1")
                    .score(900.0 + i)
                    .correlationId("tx-new-" + i)
                    .build();
            boolean accepted = queue.offer(ev);
            assert accepted : "DROP_OLDEST should evict oldest and accept new event";
        }

        assert queue.size() == capacity : "Queue size must stay bounded at capacity";
        assert queue.getDroppedCount() == 3 : "Dropped count should be 3 for evicted elements, got: " + queue.getDroppedCount();

        // The oldest remaining element should now be tx-3
        DecisionEvent firstOut = queue.poll();
        assert firstOut != null && "tx-3".equals(firstOut.getCorrelationId()) : "First element out should be tx-3, got: " + (firstOut != null ? firstOut.getCorrelationId() : "null");
    }
}
