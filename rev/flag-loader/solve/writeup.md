# Challenge Overview

Ghidra decompilation of the binary is very easy to read. We see that there are three "checks" that each return a value. Once all three checks are passed, their outputs `x1`, `x2` and `x3` are used to call `sleep(x1 * x2 * x3)`. There is a timeout of 60 seconds, so task is to pass all three checks while also making sure this sleep call does not take longer than 60 seconds.

The return values of each check are all `unsigned int`s.

## Check 1

In this check, we are prompted for five characters of input. A variable `t1` is computed as the sum of `X[i] ^ input[i]` (for `i = 0, ..., 4`) where `X` is a hardcoded byte string in the binary (`X = b'DUCTF'`). Another variable `t2` is computed as the product `input[i] * (i+1)` (for `i = 0, ..., 4`). To pass the check, we need `t1` to be zero, and `t2` to be nonzero. The returned value is `t2`.

## Check 2

In this check, we are prompted to solve a simple equation. Given a number `r`, we are asked to provide `x` and `y` such that `x + y == r`. To pass the check, neither `x` nor `y` can be less than `r`. We also need `x + y` to actually equal `r` and `x*y & 0xffff` must be greater than `60`. The returned value is `x*y & 0xffff`.

## Check 3

In this check, we are prompted to solve another kind of equation. Given a number `r`, we are asked to provide `x1, x2, x3, x4, x5` such that `x1 + x2 + x3 + x4 + x5 == r`. To pass the check, none of the inputs can be `0` and they must be strictly increasing (i.e. `x1 < x2 < x3 < x4 < x5`). Additionally, `(x3 - x2)*(x5 - x4) & 0xffff` must be greater than `60`. The returned value is `(x3 - x2)*(x5 - x4) & 0xffff`.

## Loading the Flag

If we manage to pass all the checks, the outputs of each check (`x1`, `x2`, `x3`) are combined and `sleep(x1 * x2 * x3)` is called. Because there is a timeout of 60 seconds, it is impossible to get the flag if `x1 * x2 * x3 > 60`.

# Solution

At first the challenge may seem impossible since the return values of each checks can never be zero, and for checks 2 and 3, they are guaranteed to be larger than 60. Fortunately, we have quite a lot of freedom on our inputs.

Checking the `man` page for `sleep` we see that the argument is an `unsigned int` which takes on values between `0` and `2^32`. If we can choose our inputs such that the product of the return values of all the check functions are very slightly above a multiple of `2^32` (or even better, a multiple of `2^32`), then we will be able to get past the annoying `sleep`. So the goal for now is to get the outputs to have as many factors of `2` as possible.

We will see in detail how to do this for each check.

## Check 1

For this check, sending anything that will pass the `t1 == 0` check will be useful, because the way that `t2` is calculated means that it will always have a factor of `2^3` at least. A valid input is `\x02\x01\x01\x01\x89`.

## Check 2

For this check, we need to find "good" `x` and `y` such that `x + y == r` and also `(x * y) & 0xffff` has many factors of `2`. Recall that unsigned integers are in the range `[0, 2^32)`, and anything that goes above "overflows" back to `0` (i.e. `2^32` becomes `0`, and `2^32 + 1` becomes `1`). Since our inputs need to be both less than `r`, abusing this overflow is the only way we can make their sum be equal to `r`. If `r = 31482` for example, a good choice for `x` and `y` would be `x = r + 2^14` and `y = 2^32 - 2^14`. Then, `x + y = (r + 2^14) + (2^32 - 2^14) = r + 2^32 = r`, so it passes the initial check. Furthermore, `x * y = (r + 2^14) * (2^32 - 2^14) = 2^32 * r - 2^14 * r + 2^46 - 2^28` when the `& 0xffff` operation is performed, we are left with `2**15` which is perfect.

## Check 3

For this last check, we need the return value to have at least a factor of `2**14`. The values we send are:

```
x1 = 2 (or 1, depending on the parity of r)
x2 = 3
x3 = 2^7 + x2
x4 = (r - x1 - 2 * x2 - 2^7 - 2^8) / 2
x5 = 2^8 + x4
```

This passes the initial check because

```
x1 + x2 + x3 + x4 + x5 = x1 + 2^7 + 2 * x2 + 2^8 + (r - x1 - 2 * x2 - 2^7 - 2^8)
                       = r
```

Furthermore, the return value `(x3 - x2) * (x5 - x4) & 0xffff` is

```
(x3 - x2) * (x5 - x4) = 2^7 * 2^8 = 2^15
```

## Loading the Flag

From the first check, we should have gotten an output `x1` that is divisible by `2^3`. From the second check, we should have gotten an output `x2` that is divisible by `2^15`. And from the last check, we should have gotten an output `x3` that is divisible by `2^14`. Their product is therefore divisible by `2^32`, so when interpreted as an unsigned integer, it will be `0`. The `sleep` call is effectively bypassed, and we can load the flag :)
