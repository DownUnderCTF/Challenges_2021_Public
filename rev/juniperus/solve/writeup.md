The challenge name makes reference to the infamous Juniper Networks supply-chain attack, in which a specific version of software had [embedded a root password disguised as a logging string](https://www.rapid7.com/blog/post/2015/12/20/cve-2015-7755-juniper-screenos-authentication-backdoor/) to evade detection.

Disassembling the `shell` binary, the main function (0x101180) loads the flag, and calls another function (0x101524) which contains references to log strings.
These log strings are passed, into a logging function (0x101359), with the exception of `[I] Authentication complete.`, which is passed into a separate function. This function in turn contains an inlined strcmp, and then returns its result. Hence, the player can deduce that the aforementioned string is the password.
