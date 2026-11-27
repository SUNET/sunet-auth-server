import copy
import runpy
from os import path

SAML2DIR = path.dirname(__file__)

# the settings from saml2_settings.py (which imports saml2) with two IdPs in the local metadata
SAML_CONFIG = copy.deepcopy(runpy.run_path(path.join(SAML2DIR, "saml2_settings.py"))["SAML_CONFIG"])
SAML_CONFIG["metadata"]["local"].append(path.join(SAML2DIR, "remote_metadata_idp2.xml"))
# no explicitly configured IdP, they are found in the metadata (as when using a federation)
SAML_CONFIG["service"]["sp"]["idp"] = {}
