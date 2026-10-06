package com.aievidence.sdk;

/**
 * Overflow policy when the bounded event queue reaches capacity.
 */
public enum DropPolicy {
    /**
     * Drops the newly incoming event if the queue is full.
     */
    DROP_NEWEST,

    /**
     * Discards the oldest un-delivered event in the queue to make room for the new event.
     */
    DROP_OLDEST
}
