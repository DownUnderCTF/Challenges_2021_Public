# eyespy

Note: If you are trying to complete this challenge after the CTF has concluded, please be warned that historical flight data is often only available for 14 days for free

This challenge builds on the previous as noted these are a series. Completing the challenges in order will provide a significant advantage by providing context.

For example, we know from the second challenge (Heart of the nation) that the general locality of the challenge, is in or near Canberra/ACT from the picture on Isa's website.

Similarly, from the first challenge (Who goes there) we can see that the registered name and address in the WHOIS record is Isa Haxmoore with a South Australian address. In the transcript we see the unidentified male asking Isa whether they begun settling in since moving from SA.

The transcript included in the challenge files provides the date and time of when the call took place. Within the conversation there is discussion around Isa's accomplice being recently given the USB with the decryption key on it. The unidentified male is unsure that the accomplice will make the flight, as he arrives late to the meet up with Isa.

Amongst the thrilling conversation, Isa plays a game of eye spy with the unidentified male who guesses correctly that she was looking at a plane, before Isa makes a remark about it touching down in around an hour. 

There is also a reference to Melbourne from one of the Off The Rails challenges last year (however this was more of a meme than an actual hint).

Combining these bits of information, we have the following:
- Isa is in Canberra
- A flight had taken off on the 19/09/2021 at around 1500 hours.
- It would take the flight around an hour before it touched down

If the destination hadn't been solved yet, both Melbourne and Sydney are around an hours flight from Canberra, so they would have to search for flights around the time for both of the airports and work out which fitted into the timeframe of the transcript best.

We can use online flight tracking tools such as flighradar24.com to see historical flight data from Canberra airport, although often tools like this require a departure and arrival location.

When reviewing historical flight data, there is a flight from Canberra to Melbourne on the 19/09/2021, that departed at 15:05 and took 56 minutes before arriving at Melbourne airport at 16:01. This fits the information we have, so we can grab the flight registration (YH-YIB) and destination (Melbourne).

This gives us our flag: DUCTF{VH-YIB_melbourne}