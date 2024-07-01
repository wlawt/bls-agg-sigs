### BLS Aggregated Signature Experiment

Question: Can we aggregate signatures that are already aggregated?
(i.e., aggregate aggregated signatures)

Experiment Setup: We create a simple example that builds an aggregate signature 
and aggregates it with another signature. 

Finding: We are able to verify each public key and its corresponding message with
the final aggregate signature. 

What does this mean? Open questions:
- What is the upper bound on the number of messages we can aggregate?
- Can we aggregate the entire block history with just 1 aggregated signature?
