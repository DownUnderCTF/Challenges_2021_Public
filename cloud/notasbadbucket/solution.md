# Not as Bad Bucket

This was a semi-sequel to Bad Bucket but you could do both individually. We are again presented with a URL https://storage.googleapis.com/${BUCKET_NAME}/index.html to a site which again is hosted on a bucket. Given that the challenge is again slanted towards buckets there is probably something we have to do here.

The website also notes that 
>`I was made aware of a security flare in my previous website setup, but that has been patched up and now only secret files can be accessed by logged in employees! Phew!` 

We can try to enumerate the bucket by listing its contents in the browser https://storage.googleapis.com/${BUCKET_NAME} but we get an access denied error. The hint above is pointing towards the user group of `allAuthenticatedUsers` which is a group that is allowed access to resources when you are logged in (so basically not anonymous).

To test this out we can try and list the bucket contents logged in through `gcloud`

Running

`gsutil ls gs://${BUCKET_NAME}`

We get the output of 

```
gs://${BUCKET_NAME}/index.html
gs://${BUCKET_NAME}/pics/
```

Awesome so now we can list, lets take a look in the pics/ directory

`gsutil ls gs://${BUCKET_NAME}/pics`

```
gs://${BUCKET_NAME}/pics/flag.txt
gs://${BUCKET_NAME}/pics/lisa.jpg
```

Lets go ahead and grab that `flag.txt` with

`gsutil cp gs://${BUCKET_NAME}/pics/flag.txt .`

And reading the file we get the flag!

`DUCTF{all_AUTHENTICATED_users_means_ALL_AUTHENTICATED_USERS_silly}`