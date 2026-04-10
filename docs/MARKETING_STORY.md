# Axon: How we built a 1M/sec Security Normalization Engine in Go

Security in CI/CD is broken. We’ve all been there: a simple `trivy scan` completes in seconds, but the pipeline hangs for minutes trying to parse, deduplicate, and upload a massive 500MB SARIF file. 

When we built **Axon**, we set a visceral goal: **Zero waiting.** We wanted to process security evidence at the theoretical limit of the network and CPU.

Here is the technical breakdown of how we achieved **~981,000 findings per second** using Go, NATS, and a few architectural "hacks."

---

## 1. The Death of Mutexes: The Sharded Actor Model
Standard deduplication usually involves a global map protected by a `sync.Mutex`. Under heavy concurrency (100k+ findings), mutex contention becomes the bottleneck.

**The Axon Way:** We implemented a **Sharded Actor model**. Findings aren't just thrown into a pile; they are deterministically routed to "Shards" based on a FNV-1a hash of their identity.
- Each shard is an independent "Actor" with its own local, lock-free state.
- Because a specific finding ID always routes to the same shard, we can deduplicate without ever locking a global resource.
- This allows Axon to scale linearly with CPU cores.

## 2. Zero-Copy Ingress
Most tools read a scanner report, unmarshal it into a massive struct, and then process it. This causes massive memory spikes and triggers the Go Garbage Collector (GC) to freeze the world.

**The Axon Way:** We built a streaming parser.
- Axon reads from `stdin` or disk as a raw byte stream.
- We use **byte-offset hydration**. We only parse the "Identity" of a finding (to deduplicate it). The rest of the finding data stays as a raw byte slice or pointer until the very moment it needs to be emitted.
- This keeps our memory footprint near zero, even when ingesting gigabytes of JSON.

## 3. Resilience by Design: NATS JetStream
A high-speed engine is useless if it drops data during a worker crash. 

**The Axon Way:** We integrated **NATS JetStream** as our neural buffer.
- Ingestion is decoupled from Processing. 
- We implemented an **at-least-once delivery** guarantee. Axon workers only `Ack()` a finding once it has been successfully correlated and dispatched to a sink (like Jira or Slack).
- If a worker dies mid-process, the finding is instantly re-delivered to another healthy node.

---

## The Result: Visceral Performance
In our v1.0.0 stress test, we hammered Axon with **100,000 concurrent findings** from 10 parallel streams.
- **Total Time:** ~101ms
- **Throughput:** ~981,692 findings/sec
- **Memory Contention:** Negligible.

## Why this matters
Axon isn't just about "speed for speed's sake." It's about **Developer Happiness**. By removing the friction from security data, we allow teams to actually *fix* vulnerabilities instead of managing the files that report them.

**Join the neural link:** [github.com/Mutasem-mk4/axon](https://github.com/Mutasem-mk4/axon)
