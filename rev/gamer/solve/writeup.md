# Challenge Overview

We are tasked with beating a simple game made with [Unity](https://unity.com/). Checking the network requests in the browser developer tools shows that a few files are downloaded, but while the game is being played, no network requests are made. We also note that the console output has some useful messages (though not necessary to solve the challenge). We can download the necessary assets and work offline.

The game itself is simple; collect four coins on the map, then find the flag. The first two coins are easy to get, but we are teased with the third coin being behind a tree which is blocked by a row of spikes that seem impossible to get past. If you manage to get past the spikes, the fourth coin might also seem out of reach. It exists high in the sky, surrounded by a swarm of flying enemies. If you manage to obtain this coin, the last step is to find the flag. There are signs pointing to the right, and the console output also tells you the location of the flag. It's very far away from you, and it might take some time to get there.

# Solution

To beat the game it seems like we need three things: invincibility, more jumping power, and more speed (or a position hack). Considering that everything is handled client-side, this might be possible to achieve somehow. Actually, Unity makes this quite easy for us as it exposes an interface to [call Unity scripts from JavaScript](https://docs.unity3d.com/Manual/webgl-interactingwithbrowserscripting.html). Deobfuscating and cleaning up the JavaScript in the `index.html` file, we see that `createUnityInstance` is called. We can edit the script to put the created unity instance object into the global scope so that we can use it to send messages to Unity objects (as in the link above).

## Invincibility and Jump Hack

We need to figure out what Unity objects to send messages to, and what methods are defined on them. There are some tools that may help extracting Unity assets and resources from the data files. [This tool](https://devxdevelopment.com/) (the free version) in particular could be used to get the scene data and names of the objects. However, it's entirely possible to figure out the object names with sensible guesses (i.e. `Player`) and their methods can be found by closely inspecting the `game.data` file. Specifically, the `game.data` file contains metadata for Unity scripts which includes method names. Looking through the `game.data` file, we see a section which contains some useful names.

```
PlayerLogic HandleMovement CheckIfGrounded amt BoosterJump UpdateHealth health moveSpeed jumpForce
```

Method names in C# conventionally use PascalCase, so this helps us to identify the methods. If we don't know what arguments the methods take, we can try sending messages like:

```js
unityInstance.SendMessage('Player', 'BoosterJump')
```

which will give an error message, telling us what parameters it expects:

```
Failed to call function BoosterJump of class PlayerLogic
Calling function BoosterJump with no parameters but the function requires 1.
```

Instead, if we try

```js
unityInstance.SendMessage('Player', 'BoosterJump', 20)
```

we notice that our character jumps up!

The same thing can be done for `UpdateHealth` to gain invincibility.

## Speed Hack

There aren't any convenient methods that will update our speed. Perhaps we could find where our speed is stored in memory and update it that way. However, we can also abuse the fact that Unity uses the `performance.now()` web API for handling time. Inspired by [Cetus](https://github.com/Qwokka/Cetus), we can simply overwrite `performance.now` to our own function that returns a higher value than expected; this has the effect of speeding things up and will allow us to move a lot faster. Doing this, we can move to the right and find the flag in less than a minute.

## Cheat Client

A sample cheat client can be found in `solve/index.html`. To run it, set up a http server serving at the challenge's root directory (so that it can access the files in `challenge/`). The client provides a very simple user interface to update the player's health and the game speed. It also binds `z` to the booster jump function to achieve arbitrary jump.

The GIF below shows a playthrough of the game (sorry for the screen tearing)

![playthrough.gif](./playthrough.gif)
