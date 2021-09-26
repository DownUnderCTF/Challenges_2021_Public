# Ezmail

**Catagory**: web

**Difficulty**: Medium

**Author**: todo#7331

## Flavour

Whilst performing a security assessment for a company, you notice they have a innocuous service called ezmail which allows employees to leave messages for each other. You reckon you can use this service to get the `userPassword` of the `admin` account for the whole organization.

**Flag format:** `DUCTF{[a-z0-9_]+}` case sensitive

## Description

Largely a blind ldap injection challenge with a pinch of api recon (i.e. reading the docs). Challenge involves reading leaking `userPassword` fields for ldap users in a "leave a message" application.

Players can leave messages for users by specifying their ldap common names. The lookup done to map common name -> uuid is injectable, but asynchronus to the request.
Players can build a oracle by sending a message containing a ldap injected payload. If the payload results in a value it will be reflected in the "recipients" field of the message when the message is looked up by uuid, otherwise it will be missing.

Medium challenge as most players won't have much experience with ldap, and there are a number of gotcha's that need to be understood.

## Writeup

_a solve script can be found in ./solve_

1. Players notice that the challenge is ldap - this is hinted at in the flavour text, and the world ldap is present in the docs.
2. Players notice that inputting special characters (esp `)`) as the name of a recipient will result in that recipient not appearing in the `recipients` field of the sent message.
   1. e.g. Sending a message with `an_ok_name` as well as a invalid name `)`...
      1. `POST /message {"recipients":["an_ok_name",")"], ...} -> some_message_id`
   2. ... will result in `)` disappearing from the recipients list when the message is fetched
      1. `GET /message/some_message_id -> {"recipients":["an_ok_name"]}`
3. Players notice that putting a ldap identity (e.g. `someuser)(cn=*`) as a recipient passes. This in combination with the previous fact reveals a LDAP injection.
4. The flavour text mentions to get the `userPassword` field. This can be tested with `someuser)(userPassword=*`)
5. Players do some research on ldap and learn that the `userPassword` field uses a octet string so wildcard matches don't work, there are however `strcmp`-esque operators.
6. There is a `octetStringOrderingMatch` operator on octet strings that will return results if our input is "larger" than the stored value.
7. Therefore players are able to enumerate the `userPassword` one character at a time.
    1. If the player's guess is less than or equal to the `userPassword` the recipient will be missing
    2. If the player's guess is greater than the `userPassword`, then the recipient will be present.
    3. The "highest" value that does not appear is hence a character in the password
8. Players notice they can also batch requests to perform 8 at a time.
9. Using this observation its possible to construct a blind search for the password either linearly or using a binary (or octonary) search.

## Running

`docker-compose up`

Probably can share between players if we pray to the uuid gods hard enough. :shrug:
