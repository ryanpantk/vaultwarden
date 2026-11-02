"""Check custom invite URLs against a disposable running Vaultwarden instance.

Creates one pending test user. Run with VAULTWARDEN_TEST_URL and
X_VAULTWARDEN_API set; use --insecure only for local self-signed TLS.
"""

import argparse
import json
import os
import ssl
import uuid
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()
    base = os.environ["VAULTWARDEN_TEST_URL"].rstrip("/")
    key = os.environ["X_VAULTWARDEN_API"]
    context = ssl._create_unverified_context() if args.insecure else ssl.create_default_context()
    email = f"invite-regression-{uuid.uuid4().hex}@example.test"

    def request(path, data=None, authenticated=True):
        headers = {"Content-Type": "application/json"}
        if authenticated:
            headers["x-vaultwarden-api"] = key
        payload = json.dumps(data).encode() if data is not None else None
        with urlopen(Request(base + path, data=payload, headers=headers), context=context, timeout=20) as response:
            return json.load(response)

    try:
        request("/custom/invite", {"email": email}, authenticated=False)
    except HTTPError as error:
        assert error.code == 401, f"Expected 401, got {error.code}"
    else:
        raise AssertionError("Unauthenticated invitation was accepted")

    user = request("/custom/invite", {"email": email})
    assert user["userId"], "Invitation did not return a user ID"
    response = request("/custom/user/invite-link?" + urlencode({"email": email}))
    link = urlsplit(response["inviteLink"])
    route, query = link.fragment.split("?", 1)
    params = parse_qs(query, keep_blank_values=True)
    assert route.rstrip("/") == "/accept-organization", route
    assert params.get("initOrganization") == ["false"], "Missing/invalid initOrganization"
    assert params.get("orgUserHasExistingUser") == ["false"], "Missing/invalid new-user flag"
    assert params.get("email") == [email], "Invitation email mismatch"
    for field in ("organizationId", "organizationUserId"):
        uuid.UUID(params[field][0])
    assert params.get("organizationName", [""])[0], "Missing organization name"
    assert params.get("token", [""])[0], "Missing invitation token"
    print("PASS: API authentication and new-user invitation URL contract")


if __name__ == "__main__":
    main()
