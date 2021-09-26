# Floormat

**Category:** Misc
**Difficulty:** Easy
**Author:** todo#7331

_I've opened a new store that provides free furnishings and floormats. If you know the secret format we might also be able to give you flags..._

# Description
Python is vulnerable to format strings ({format_identifier}'s in strings). If these are provided with a class (or other "class like" object) it is possible to gain a read primitive in much the same was as template injection. Here we use it to read the `FLAG` variable in the global scope.

## Writeup

_A solve script can be found in ./solve_

1. Trigger a custom floormat design by specifying something other than the provided options
2. Provide a format string that reads a flag from the global scope `{f.__class__.__init__.__globals__[FLAG]}`
3. Trigger the format string by specifying a arbitrary (expected) input
4. Get the flag

## Running

Please provide the file under publish/ to the player.

The challenge can be run by building and running the docker file, it listens on port 1337 by default.
