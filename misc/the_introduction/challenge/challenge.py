#!/usr/bin/python3.8
import sys, time, random

def typer(text2type):
        for l in text2type:
                sys.stdout.write(l)
                sys.stdout.flush()
                time.sleep(random.random()*10.0/240)
        return " "

flag = r"""
                   __
                  / \--..____
                   \ \       \-----,,,..
                    \ \       \         \--,,..
                     \ \       \         \  ,'
                      \ \       \         \ ``..
                       \ \       \         \-''
                        \ \       \__,,--'''
                         \ \       \.
                          \ \      ,/
                           \ \__..-
                            \ \
                             \ \
                              \ \   
                               \ \
                                \ \
                                 \ \
                                  \ \
                                   \ \
                                    \ \

"""

manifesto = """
        Another one got caught today, it's all over the papers.  "Teenager
Arrested in Computer Crime Scandal", "Hacker Arrested after Bank Tampering"...
        Damn kids.  They're all alike.

        But did you, in your three-piece psychology and 1950's technobrain,
ever take a look behind the eyes of the hacker?  Did you ever wonder what
made him tick, what forces shaped him, what may have molded him?
        I am a hacker, enter my world...
        Mine is a world that begins with school... I'm smarter than most of
the other kids, this crap they teach us bores me...
        Damn underachiever.  They're all alike.

        I'm in junior high or high school.  I've listened to teachers explain
for the fifteenth time how to reduce a fraction.  I understand it.  "No, Ms.
Smith, I didn't show my work.  I did it in my head..."
        Damn kid.  Probably copied it.  They're all alike.

        I made a discovery today.  I found a computer.  Wait a second, this is
cool.  It does what I want it to.  If it makes a mistake, it's because I
screwed it up.  Not because it doesn't like me...
                Or feels threatened by me...
                Or thinks I'm a smart ass...
                Or doesn't like teaching and shouldn't be here...
        Damn kid.  All he does is play games.  They're all alike.

        And then it happened... a door opened to a world... rushing through
the phone line like heroin through an addict's veins, an electronic pulse is
sent out, a refuge from the day-to-day incompetencies is sought... a board is
found.
        "This is it... this is where I belong..."
        I know everyone here... even if I've never met them, never talked to
them, may never hear from them again... I know you all...
        Damn kid.  Tying up the phone line again.  They're all alike...

        You bet your ass we're all alike... we've been spoon-fed baby food at
school when we hungered for steak... the bits of meat that you did let slip
through were pre-chewed and tasteless.  We've been dominated by sadists, or
ignored by the apathetic.  The few that had something to teach found us will-
ing pupils, but those few are like drops of water in the desert.

        This is our world now... the world of the electron and the switch, the
beauty of the baud.  We make use of a service already existing without paying
for what could be dirt-cheap if it wasn't run by profiteering gluttons, and
you call us criminals.  We explore... and you call us criminals.  We seek
after knowledge... and you call us criminals.  We exist without skin color,
without nationality, without religious bias... and you call us criminals.
You build atomic bombs, you wage wars, you murder, cheat, and lie to us
and try to make us believe it's for our own good, yet we're the criminals.

        Yes, I am a criminal.  My crime is that of curiosity.  My crime is
that of judging people by what they say and think, not what they look like.
My crime is that of outsmarting you, something that you will never forgive me
for.

        I am a hacker, and this is my manifesto.  You may stop this individual,
but you can't stop us all... after all, we're all alike.

                               +++The Mentor+++"""


name = input(typer("wh47 15 y0ur n4m3 h4ck3r?"))

if (name):
    print()
    typer("Here are some wise words " + name + ":")
    print()
    typer(manifesto)
    print()
    print()
    choice = input(typer("50 4r3 y0u 4c7u4lly 4 h4ck3r? "))
    while(choice != "yes"):
        choice = input(typer("50 4r3 y0u 4c7u4lly 4 h4ck3r? "))
    print()
    typer(name + ", y0u w1ll n33d 7h15 0n y0ur duc7f j0urn3y 7h3n")
    print()
    print()
    typer("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print()
    print()
    typer("DUCTF{w3lc0m3_70_7h3_duc7f_7hund3rd0m3_h4ck3r}")
    print()
    print()
    typer("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print()
    print()
    typer(flag)
    print()
    print()
else:
    print(" ¯\_(ツ)_/¯ no flag then ¯\_(ツ)_/¯")
