import copy
import runpy
from os import path

SAML2DIR = path.dirname(__file__)

# the settings from saml2_settings.py (which imports saml2) with the IdP from an MDQ server instead of local metadata
SAML_CONFIG = copy.deepcopy(runpy.run_path(path.join(SAML2DIR, "saml2_settings.py"))["SAML_CONFIG"])
SAML_CONFIG["service"]["sp"]["idp"] = {}
SAML_CONFIG["metadata"] = {"mdq": [{"url": "http://mdq.example.com"}]}
