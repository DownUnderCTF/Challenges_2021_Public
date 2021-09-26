# Jasons Proxy Write Up

1. Create a new POST request to `/jason_loader` with the following POST body
```
{"img":"aHR0","img":"aHR0cDovLzEyNy4wLjAuMS9zdGF0aWMvaW1hZ2VzLyUyZSUyNTJlLyUyZSUyNTJlLyUyNTYxZG1pbi9mbCUyNTYxZw=="}
```

The above payload first exploits the vulnerability inside of the JSON parsing function where it fails to double check "checked" keys, bypassing the character filter. The payload must start with the string `http://127.0.0.1/static/images/` so the rest of the payload is a directory traversal double URL encoded to bypass checks at the proxy level. Finally the proxy requests the path `http://127.0.0.1/admin/flag`, the proxy then encodes the flag data in base64 and sends it back to the player.

2. Observe the flag data returned in base64 encoded form

```
{"imagedata": "RFVDVEZ7ZDB1YmwzX2pzMG5fZDB1YmwzX1VSSV9yMXBfajRzMG41X3A0dGhfdzF0aF9iMWdfaDR4eH0="}
```