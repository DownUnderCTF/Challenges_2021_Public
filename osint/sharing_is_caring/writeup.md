# Sharing is Caring

We are given a username alex_elgato93, and a hint that the user might have made a mistake up somewhere in their social media posts. We need to find the street closest to their location.

The first step is to use a username lookup tool to search up accounts with the username **alex_elgato93**. This will return the following accounts, which all seem to be owned by the same person, with the same display picture.

- https://www.twitch.tv/alex_elgato93
- https://twitter.com/alex_elgato93
- https://www.pinterest.com.au/alex_elgato93/
- https://steamcommunity.com/id/alex_elgato93

These accounts reveal alex_elgato93's name to be Alexandros Elgato.

Alexandros seems to be the most active on his twitter account.
If you check his steam account, you can see he previously used his full name as his username: **alexandros-elgato**.

If you look up the username alexandros-elgato you will find some more accounts:

- https://github.com/alexandros-elgato
- https://www.reddit.com/user/alexandros-elgato

Reddit seems to be the place Alexandros is the second most active.

After exploring the various posts Alexandros has made, you will find a post with a screenshot of a Kali VM open in VirtualBox.

In the screenshot Alexandros has various windows open, unintentionally including ARP command output with a MAC address: **DE:73:2C:6C:1B:C1**

Searching this MAC address up with https://wigle.net/ will show that Alexandros has connected to an access point at a location (randomly chosen by us) in NSW. The road that Alexandros is closes to according to Wigle is Charles McIntosh Pkwy.

We'll end up with one of the following two flags:
- *DUCTF{charles_mcintosh_pkwy}*
- *DUCTF{charles_mcintosh_parkway}*

Note: The flag for this challenge was initially incorrectly set as DUCTF{charles_mckintosh_parkway}. This was identified and resolved within 30 minutes of challenge release, and a notification was sent out on discord and CTFd.