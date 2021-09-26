# Not as Bad Bucket

**Creator:** Blue Alder

**Category:** cloud

**Difficulty:** easy

## Flavortext

Okay fine I admit it, we didn't invest in security in my previous website and we learnt our lesson. Luckily we had a Professional Cloud Architect, architect our new security strategy for our website 2.0!
https://storage.googleapis.com/${BUCKET_NAME}/index.html

## Quick Overview of exploit
Bucket is configured to allow all authenticated users to list and view, looking at the root directy with `gsutil` we can see a flag at pics/flag.txt

Flag: DUCTF{all_AUTHENTICATED_users_means_ALL_AUTHENTICATED_USERS_silly}
