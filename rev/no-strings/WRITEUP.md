When we run the program, we are prompted to enter the flag. If we enter something, the program prints `wrong!` and exits. Presumably, the goal of the challenge is to reverse engineer the program to figure out what input string will cause the program to print something other than `wrong!`.

[`strings`](https://en.wikipedia.org/wiki/Strings_(Unix)) is a useful program that can be used to quickly find hardcoded strings (and secrets!) in binary files. In this challenge however, running `strings` does not find the flag as one might expect from the challenge name. Here are two (among many other) ways to solve the challenge:

- Running `xxd` and looking through the output reveals something that resembles the flag (which we can recognise from the `DUCTF{` flag format)
- Opening the binary in `radare2` and running the `iz` command to print strings in the data sections of the binary
