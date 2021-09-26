# Solution
1. First step is to determine the profile and OS of the memory dump - (with volatility)
```
vol.py -f JacobsPC.raw imageinfo
```
2. Let's start by determining which processes were running at the time of the dump
```
vol.py -f JacobsPC.raw --profile=Win7SP1x64 pslist
```
3. There are a large number of processes that were running on the host, however, one immediately sticks out the most - drpbx.exe (PID 3628) - diving deeper by having a look at the dll list
```
vol.py -f JacobsPC.raw --profile=Win7SP1x64 dlllist -p 3628
```
4. This list shows 3 points of interest, the first is a strange executable file simulating dropbox - C:\Users\Jacob\AppData\Local\Drpbx\drpbx.exe - the other two points of interest are CRYPTBASE.dll and CRYPTSP.dll. Whilst these are standard Windows dll's, these two in combination are quite common among Windows ransomware.

5. A quick google search for drpbx.exe leads to Jigsaw ransomware. The original process that is utilised by this ransomware is drpbx.exe, to maintain persistence jigsaw updates the startup registry to run an executable in the users App Data folder - ...\Roaming\Frfx\firefox.exe. We can confirm that this is the persistence method utilised in this case by running the following:
```
vol.py -f JacobsPC.raw --profile=Win7SP1x64 printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"
```
6. The last step in to achieve the flag is to determine the originating folder name where the infection began. For this, we can have a look at the 'handles' for the drpbx.exe process.
```
vol.py -f JacobsPC.raw --profile=Win7SP1x64 handles -p 3628 -t file
```
7. By filtering on File handles we can see files and folders related to the process. There is one folder early on in the processes memory stream that is different to the others - \Device\HarddiskVolume2\Users\Public\Videos\Sample Videos\PJxhJQ9yUDoBF1188y - this is likely the folder where the ransomware was launched from.

Therefore, putting these findings together the flag is:
```
DUCTF{jigsaw_firefox.exe_PJxhJQ9yUDoBF1188y}
```
