package com.aievidence.sdk;

import java.util.ArrayList;
import java.util.List;

/**
 * Enterprise Standalone Test Runner: Executes all unit, SLA, resilience, and approval
 * test suites using standard JDK 17 runtime with zero external dependencies.
 */
public class TestRunner {

    interface TestCase {
        String name();
        void run() throws Exception;
    }

    public static void main(String[] args) {
        System.out.println("======================================================================");
        System.out.println("AI EVIDENCE JAVA SDK - ENTERPRISE TEST SUITE (JDK 17 LTS)");
        System.out.println("======================================================================");

        List<TestCase> suites = new ArrayList<>();
        suites.add(new TestCase() {
            public String name() { return "EvidenceClientTest (Functional & Lifecycle)"; }
            public void run() throws Exception { new EvidenceClientTest().runAll(); }
        });
        suites.add(new TestCase() {
            public String name() { return "LatencySlaTest (< 5.0ms Non-Blocking SLA)"; }
            public void run() throws Exception { new LatencySlaTest().runAll(); }
        });
        suites.add(new TestCase() {
            public String name() { return "BufferOverflowTest (Capacity & Drop Policies)"; }
            public void run() throws Exception { new BufferOverflowTest().runAll(); }
        });
        suites.add(new TestCase() {
            public String name() { return "ResilienceTest (Fault Isolation & Zero Exception)"; }
            public void run() throws Exception { new ResilienceTest().runAll(); }
        });
        suites.add(new TestCase() {
            public String name() { return "ApprovalWorkflowTest (Asynchronous Polling & 4-Eyes)"; }
            public void run() throws Exception { new ApprovalWorkflowTest().runAll(); }
        });
        suites.add(new TestCase() {
            public String name() { return "AdversarialChallengeTest (Stress SLA, Dead Port, Overflow & Lifecycle)"; }
            public void run() throws Exception {
                try {
                    new AdversarialChallengeTest().runAll();
                } catch (Throwable t) {
                    if (t instanceof Exception) throw (Exception) t;
                    throw new RuntimeException(t);
                }
            }
        });

        int passed = 0;
        int failed = 0;
        long overallStart = System.currentTimeMillis();

        for (TestCase tc : suites) {
            System.out.println("[*] Running: " + tc.name());
            long start = System.currentTimeMillis();
            try {
                tc.run();
                long elapsed = System.currentTimeMillis() - start;
                System.out.println("    -> PASSED (" + elapsed + "ms)");
                passed++;
            } catch (Throwable t) {
                long elapsed = System.currentTimeMillis() - start;
                System.err.println("    -> FAILED (" + elapsed + "ms): " + t.getMessage());
                t.printStackTrace(System.err);
                failed++;
            }
        }

        long totalTime = System.currentTimeMillis() - overallStart;
        System.out.println("======================================================================");
        System.out.printf("SUMMARY: %d suites ran, %d passed, %d failed in %dms%n",
                suites.size(), passed, failed, totalTime);
        System.out.println("======================================================================");

        if (failed > 0) {
            System.err.println(">>> OVERALL RESULT: TEST SUITE FAILED <<<");
            System.exit(1);
        } else {
            System.out.println(">>> OVERALL RESULT: ALL JAVA SDK TESTS PASSED (100% SUCCESS) <<<");
            System.exit(0);
        }
    }
}
