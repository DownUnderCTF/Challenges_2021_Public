# How to pronounce GIF?

The gif is moving fast, while you could try to record the screen or load the gif into an graphics application to see all of the frames, the quickest method would be to use online tools to extract all of the frames from the gif. An example that worked well is: [https://ezgif.com/split](https://ezgif.com/split)

Extracting all of these frames (so long as you did them in order) you will notice that there are 10 sets of QR Codes, either due to the 10 "starts" or QR codes or that each is a different style and/or colour.

One you've identified the 10 different QR Codes you can script the joining of image 0, 10, 20, 30, ... , 110 makes up a single QR Code, then continue for the next 9 QR Codes. Of course, you could also manually stitch these together by hand if your scripting would be slower...though the learning experience from scripting this is really the goal!

The QR Codes in order:

1. bit.ly link to Youtube how to pronounce Gif
2. Text saying the princess is in another castle
3. bit.ly link to Youtube with Jimmy Barnes screaming for 10 hours
4. leetspeak saying "follow the white rabbit"
5. bit.ly to Youtube rickroll
6. ascii art of a rabbit (hopefully hint that it's next...)
7. first half of base64 flag (RFVDVEZ7YU1)
8. bit.ly link to youtube All Your Base (base64 hint)
9. second half of base64 flag (fMV9oYVhYMHJfbjB3P30=)
10. ascii art of a shocked rabbit

The flag "RFVDVEZ7YU1fMV9oYVhYMHJfbjB3P30=" should be quickly identified as base64 due to the characters used (uppercase, lowercase, 0-9, =\) or the fact that it ends with an equals sign (base64 can end with 0, 1 or 2 equal signs, used as a kind of padding to make sure decoding works). Decoding this (a number of ways you can do this, though a great online site is [https://www.base64decode.org/](https://www.base64decode.org/)) will give you the flag.

Hope you enjoyed it!

---

## Flag

DUCTF{aM_1_haXX0r_n0w?}