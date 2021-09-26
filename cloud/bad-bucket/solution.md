# Bad Bucket

So this was an easy challenge about basic bucket permissions. We are presented with a url as an entry point into the challenge https://storage.googleapis.com/${BUCKET_NAME}/index.html. This URL denotes that the website is hosted on a bucket.

The website also points towards buckets as a hint. We can try and list the contents of the bucket by navigating up a directory 

https://storage.googleapis.com/${BUCKET_NAME}

We get an XML output which shows a few interesting files, notably

```xml
<Contents>
<Key>buckets/.notaflag</Key>
<Generation>1627459441112582</Generation>
<MetaGeneration>1</MetaGeneration>
<LastModified>2021-07-28T08:04:01.113Z</LastModified>
<ETag>"d66c1be5db93f7b0fd7a63b01f4abeb1"</ETag>
<Size>158</Size>
</Contents>
```

Navigating to this file to download the file 

https://storage.googleapis.com/${BUCKET_NAME}/buckets/.notaflag

We open the file and we recieve the flag!

`DUCTF{if_you_are_beggining_your_cloud_journey_goodluck!}`