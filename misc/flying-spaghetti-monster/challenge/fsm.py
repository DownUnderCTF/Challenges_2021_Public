import inspect
import itertools
import json
import random
import string

import networkx
import sympy

GEN_CHUNK = 8192
x = sympy.symbols("x")

def linfunc_gen(n=None):
    i = 0
    if n is None:
        gi = itertools.count()
    else:
        gi = range(n // GEN_CHUNK + 2)
    ps = iter(sympy.ntheory.generate.Sieve())
    for i in gi:
        cs = random.sample(range(GEN_CHUNK), GEN_CHUNK)
        for p, c in zip(ps, cs):
            yield sympy.Poly(p * x + c + (i * GEN_CHUNK), x)

class FSM():
    def __init__(self, g):
        self.g = g

    @classmethod
    def new(cls, alphabet=string.printable):
        # We shuffle the alphabet so that monotonic state numbers don't leak it
        alphabet = list(alphabet)
        random.shuffle(alphabet)
        g = networkx.complete_graph(alphabet, create_using=networkx.DiGraph)
        # Add loop edges so we can repeat characters
        for n in g.nodes:
            g.add_edge(n, n)
        # Now generate random linear functions for each edge
        ec = len(g.edges)
        for e, f in zip(random.sample(tuple(g.edges), ec), linfunc_gen(ec)):
            ed = g.edges[e]
            ed["f"], ed["n"] = f, ord(e[1])
            ed["fe"] = fe = f.as_expr()
        # Now that we've added the values to the edges, we can anonymise the
        # node into a monotonic series of integer values
        return cls(networkx.convert_node_labels_to_integers(g))

    @classmethod
    def load(cls, fobj):
        g = networkx.DiGraph()
        for edge_repr in fobj.readlines():
            a_b, n, fe = edge_repr.strip().split("\t")
            a, b = a_b.split("->")
            a, n, b = map(int, (a, n, b))
            f = sympy.Poly(fe)
            g.add_edge(a, b, n=n, f=f, fe=fe)
        return cls(g)

    def save(self, fobj):
        for a, b in random.sample(tuple(self.g.edges), len(self.g.edges)):
            ed = self.g.edges[(a,b)]
            fobj.write(f"{a}->{b}\t{ed['n']}\t{ed['fe']}\n")

    def as_edges(self, inputs):
        # Convert an input iterable into a series of edge traversals. Note that
        # we add an extra edge from the 0th element to itself to ensure it is
        # explicitly included in the edge list.
        first, *rest = inputs
        for e in networkx.selfloop_edges(self.g):
            if self.g.edges[e]["n"] == ord(first):
                yield e
                a = e[0]
                break
        else:
            raise LookupError(f"Failed to find loop edge for {first!r}")
        for c in rest:
            for b, ed in self.g[a].items():
                if ed["n"] == ord(c):
                    yield a, b
                    a = b
                    break
            else:
                raise LookupError(f"Failed to find edge from {a!r} for {c!r}")

    def get_comp(self, inputs):
        # Compose the linear functions along a path of input values
        fa = sympy.Poly(x)
        for e in self.as_edges(inputs):
            fb = self.g.edges[e]["f"]
            fa = fb.compose(fa)
        return fa, e[1]

if __name__ == "__main__":
    print("Creating new FSM")
    fsm_obj = FSM.new()
    fsm_obj.save(open("fsm.txt", "w"))
    print("Creating canned challenges")
    canned_data = []
    for data in (l.strip() for l in open("canned-inputs.txt").readlines()):
        if not data or data.startswith("#"):
            continue
        data, *maybe_timeout = data.split(";")
        f, sf = fsm_obj.get_comp(data)
        datum = {
            "data": data,
            "f_expr": str(f.as_expr()),
            "final_state": sf,
        }
        if maybe_timeout:
            (timeout, ) = maybe_timeout
            datum["timeout"] = int(timeout)
        canned_data.append(datum)
    json.dump(canned_data, open("canned.json", "w"))
    print("Done")
