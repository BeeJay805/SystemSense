SYSTEMSENSE NORTH STAR



SystemSense is a fast adaptive computer investigator.



The primary behavior is:



1\. Observe computer state.

2\. Maintain a changing search space of evidence, entities, relationships,

&#x20;  hypotheses and possible measurements.

3\. Keep Laya warm and continuously use it as the fast learned search policy.

4\. Laya rapidly ranks many meaningful choices while useful work exists.

5\. Selected measurements begin immediately without waiting for unrelated work.

6\. The deep reasoning model operates asynchronously and changes the search

&#x20;  strategy without blocking Laya.

7\. Deterministic code owns truth, permissions, execution and verification.

8\. Converge on a supported diagnosis and, when authorized, a verified fix.



PERFORMANCE INTENT



Laya is not an occasional filter before the LLM.

It should behave like an extremely fast intelligent search algorithm over the

computer's changing state.



When enough useful candidates exist, SystemSense should continuously process

and rank them using batching and incremental invalidation.



The primary system should optimize:

time to useful evidence

time to supported diagnosis

time to verified recovery



NOT:

number of tests

number of abstractions

number of model calls

amount of telemetry collected



DEPLOYMENT



Consumer:

local observation/control + cloud fast model + cloud deep model.



Open source:

same architecture with replaceable fully local models.



Local model resource constraints must not distort the consumer architecture.



DEVELOPMENT RULE



When choosing between:

A) another generalized infrastructure abstraction

B) proving the complete investigation loop



prefer B unless A is required for correctness of that exact loop.



A milestone is not complete because its components exist individually.

It is complete when the intended end-to-end behavior is demonstrated.



This file supersedes older product-direction documents when they conflict.
