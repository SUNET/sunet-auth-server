import copy
import runpy
from os import path

SAML2DIR = path.dirname(__file__)

# Test-only settings where signatures are required: want_response_signed and want_assertions_signed are not set so
# the loader defaults (True) apply. The IdP metadata holds the certificate of the test-only key
# certs/test_idp_signing.key, never use these keys or certificates anywhere else.
SAML_CONFIG = copy.deepcopy(runpy.run_path(path.join(SAML2DIR, "saml2_settings_compat.py"))["SAML_CONFIG"])
SAML_CONFIG["metadata"]["local"] = [path.join(SAML2DIR, "remote_metadata_signed.xml")]
