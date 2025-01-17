from time import sleep

import requests

cert = "path/to/cert.crt"
key = "path/to/cert.key"
cert_fingerprint = "cert finterprint"
server = "https://url.to.auth.server/"

if not all([cert, key, cert_fingerprint, server]):
    print("Missing configuration")

s = requests.Session()
s.verify = False

grant_req = {
    "access_token": [{"flags": ["bearer"]}],
    "client": {
        "key": {
            "proof": {"method": "mtls"},
            "cert#S256": cert_fingerprint,
        }
    },
    "interact": {"start": ["user_code_uri"]},
    "subject": {
        "assertion_formats": ["saml2"],
        # "authentication_context": ["https://refeds.org/profile/mfa"]
    },
}

continue_resp = s.post(url=f"{server}/transaction", cert=(cert, key), json=grant_req)
if continue_resp.status_code != 200:
    raise (Exception(continue_resp.text))
res = continue_resp.json()
print()
print(f"Go to {res['interact']['user_code_uri']['uri']} and use code: {res['interact']['user_code_uri']['code']}")
print()
do_continue_req = True
wait = int(res["continue"]["wait"])
while True:
    print(f"Waiting for {wait} seconds...")
    sleep(wait)
    headers = {"Authorization": f"GNAP {res['continue']['access_token']['value']}"}
    grant_resp = s.post(url=f"{res['continue']['uri']}", cert=(cert, key), headers=headers)
    _continue = grant_resp.json().get("continue")
    if _continue is None:
        break
    wait = int(_continue["wait"])
print()
print("Grant response:")
print(f"{grant_resp.json()}")
