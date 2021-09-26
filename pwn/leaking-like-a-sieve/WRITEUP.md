
# Leaking like a sieve solution

This challenge features a beginner PWN vulnerability - format string vulnerability.

## Format string vulnerabilities

When a format argument such as %s, %d, etc is not specified when printing variables using printf, scanf in C then user input can be passed as a format argument.

This allows the user to leak data using printf as it pops data off the stack as it is a variadic function.

## Solving the challenge
### Identify the vulnerability
To solve this challenge, the user will need to identify first that the vulnerability is a format string vuln.

This can be done one of two ways, inferring from the challenge title and description that data is being leaked and searching online for data leakage vulnerabilities.

Alternatively, the user can reverse engineer the compiled binary using Ghidra or similar tools to identify the usage of printf and lack of format arguments.

### Exploit time

From here, the user will need to iterate through different format arguments such as %x, %d, %s and subsequently the correct index/quantity
of the argument to leak. This is be achieved using %n$x where n is a decimal index.

Due to the way the stack is allocated by the compiler, `flag` is at a lower address on the stack (index/argument ) and is also a string, so to leak the flag you would enter %6$s.


## Exploit:

```
What is your name?
%6$s

Hello there, DUCTF{f0rm4t_5p3c1f13r_m3dsg!}
```
