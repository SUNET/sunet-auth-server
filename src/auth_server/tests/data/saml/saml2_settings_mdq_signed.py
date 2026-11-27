import copy
import runpy
from os import path

SAML2DIR = path.dirname(__file__)

# the MDQ settings, but the metadata must be signed by the test-only cert certs/test_idp_signing.crt
SAML_CONFIG = copy.deepcopy(runpy.run_path(path.join(SAML2DIR, "saml2_settings_mdq.py"))["SAML_CONFIG"])
SAML_CONFIG["metadata"]["mdq"][0]["cert"] = path.join(SAML2DIR, "certs", "test_idp_signing.crt")
