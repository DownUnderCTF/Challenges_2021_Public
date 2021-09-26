# Whale Blog

**Creator:** Blue Alder

**Category:** cloud

**Difficulty:** medium

## Flavortext

You're probably thinking, oh wow here is another challenge author thinking they would be smart by having the word `whale` in the challenge title, oh wow it's probably Docker. Well you're right whale=docker this challenge has to do with docker. Get that flag⛳.

whale-blog.duc.tf

## Quick Overview of exploit
LFI in the main page on a kubernetes deployment means they can get service account token. Use token to read secrets on the Kube cluster by connecting to it directly.

Flag: DUCTF{g00nies_got_th1s_l4st_year_now_u_did!}