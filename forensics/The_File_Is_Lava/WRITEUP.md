# Challenge writeup

### Scenario:

Forensic investigators believe this machine might have been involved to perform data exfiltration. 

The method used here is a straightforward way to go about the investigation. Parts of this can be scripted if the player is advanced enough to know what they are looking for.
Other artefacts may also be used and other tools can be used to gather the same information.
The idea behind this ctf is not based around a tool, but rather the logic of finding relevant artefacts and then applying logical thinking to spot anomalies. 

You are told that the machine is related to an incident in where ***data exfiltration*** was performed. 

This suggests that files on the system were ***moved to someplace other than where they originated***.

There are many resources on how to go about windows forensics, among the best are SANS. This poster here tells us what artefacts we might look for when dealing with files that might have been accessed.

## Where do I start?

I will take a look at the LNK files as they pack a lot of information, especially timestamps. 

Generally, someone looking to steal files will have a look at those files to know what is in them. This means they will ***access the file***. 

Whenever a file is accessed, a `.lnk` file is created and stays on the machine, even if the target file is deleted.  These files are located in the recents folder.

I will use a tool from Eric Zimmerman called `LECmd` to parse these files in a csv format.
The tool is small and is a standalone executable that can be run from a USB plugged into the virtual machine. 

Tool link: [https://ericzimmerman.github.io/#!index.md](https://ericzimmerman.github.io/#!index.md)

⚠There are other tools to look at these, and you can even do so directly.

Generally, when conducting forensics on a machine, you want to avoid disturbing forensic data. I use a USB with the tool executable file on it. 

I just plug in the USB, and run the tool using Command prompt. The command for the tool on my machine is as follows:

```bash
LECmd.exe -d C:\Users\ductf\AppData\Roaming\Microsoft\Windows\Recent -q --csv E:
```

Note: The `E:` is the location of my USB where I want the file to be outputted. 

This just presents the format in a `.csv` that made it easy for me to then visually see the metadata of the `.lnk` file itself and the target file.

## The Flag

When you look at the CSV file, look for the row that has "Executive Management report".

If you find this row, and then scroll to see the metadata fields, namely the volume label and the localDirectory name, you will find two bits of base64 code:

- RFVDVEZ7eTB1X2YwdW5kX3Ro
- M19tMXNzMW5nX2wxbmt9

Put them in cyberchef and you will have the flag of `DUCTF{y0u_f0und_th3_m1ss1ng_l1nk}`

This was written knowing where the flag is, but the user is might choose other tools these hidden metadata jems :)
