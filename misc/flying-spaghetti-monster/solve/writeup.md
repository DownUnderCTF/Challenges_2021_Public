## Flying Spaghetti Monster

This is a challenge that presents something which looks roughly like a finite
state machine, defined by its state transitions. Each transition is defined by
an integer value (all of which are ASCII printables) and a polynomial of the
form `a*x + c` where `a` is prime and `c` is in Z+. Each state is labelled
using a monotonic sequence of values which don't correspond to the values
associated with each state transition. The player is given this information as
a static handout, and the server must have the same data available to it.

The player connects to a server for the live component of the challenge. The
server presents a series of challenges where the player is given a large
polynomial and a single integer value. These are the result of composing each
of the polynomials along a series of state transitions, and the label of the
state the machine "terminated" at. e.g in the following undirected machine:

                                       X
                                     /   \
                   0x42, 3 * x + 7  /     \  0x41, 7 * x + 3
                                   /       \
                                  /         \
                                 Y --------- Z
                                0x43, 11 * x + 6

If we wanted to challenge the player to provide the string "BC", we'd take the
path from X -> Y -> Z which have the two ASCII values we need. That path would
cause us to construct the composition:

```
YZ(XY(x)) = 11 * (3 * x + 7) + 6 -> 33x + 83
```

Since composition of linear functions isn't generally commutative, if we give
the player the final state of the machine (Z in this case), they can work
backward, decomposing the polynomial along candidate paths in the state graph.
It's pretty easy to prune bad paths by avoiding edges which don't have an `a`
coefficient which factors the current decomposed polynomial's `a`, or if the
current decomposed `c` minus the edge's `c` isn't factored by the edge's `a`
(which is the check the solver uses). They could also prune the full state
graph immediately using the prime factorisation of the `a` from the challenge
they are given, but I found that spending time building the reduced graph
dominated execution and it wasn't worth it since we still traverse the full
graph pretty quickly.

It's worth noting that the challenge uses a complete digraph with self-loops
for each node to make it seem more complicated. That means that the edge X -> Y
in the example above would be different to the edge Y -> X if it were
constructed like the real challenge's machine. The premise works with an
undirected graph as well since each state is roughly associated with a "last
ASCII value" traversed. ie. all inbound edges to a node have the same integer
value, so the fact that X -> Y is different to Y-> X doesn't really matter
because even with an unidirected graph we could statefully interpret the path
X -> Y -> X -> Y ... as long as we know the final state of that path.

## Stumbling blocks

So the player is challenged with progressively larger polynomials to walk
backward along, and increasingly restrictive time limits (using SIGALRM on a
Python `input()` call). This is partially intended to act as a rough PoW to
avoid people trying to DoS the server, but also to give them an opportunity to
learn the system with simple challenges before we force them to script a
solution.

There are a few steps of optimsation I might expect someone to go through:
 * realising that factoring large ints in Python is slow
   - I swapped to using GNU `factor` via `subprocess`
 * realising that reducing the graph is expensive and unnecessary
   - Lazy people might not even do this in the first place, :+1:
 * realising that factoring the given `a` isn't necessary
   - since a single `divmod(c_decomp - c_edge, a_edge)` is enough to work out
     if an edge is good candidate
   - this is ideally "required" to finish the final challenge on time
