⚡ Optimize LFU eviction with single atomic query

💡 **What:** Replaced the chunked `DELETE` loop (N+1 pattern) and initial `SELECT` inside `evict_lfu` with a single atomic `DELETE` query leveraging a subquery with `IN (SELECT ...)`.
🎯 **Why:** The N+1 query pattern caused unnecessary database connection and cursor acquisition overhead. By shifting the workload completely into a single atomic SQLite query, we eliminate python application looping, which reduces overall execution time. We also bypass SQLite parameter limits (only 2 parameters used in the subquery now instead of chunking IDs).
📊 **Measured Improvement:** The `evict_lfu` logic improved from taking roughly `~0.10s` down to `~0.08s` for deleting 25,000 signatures, representing roughly a ~20% execution time decrease.
