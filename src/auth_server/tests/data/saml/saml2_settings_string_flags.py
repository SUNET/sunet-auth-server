__author__ = "lundberg"

import copy
import runpy
from os import path

SAML2DIR = path.dirname(__file__)

# the settings from saml2_settings.py with the signature flags as strings, which pygamlastan accepts and converts to
# False but which are truthy in Python
SAML_CONFIG = copy.deepcopy(runpy.run_path(path.join(SAML2DIR, "saml2_settings.py"))["SAML_CONFIG"])
SAML_CONFIG["service"]["sp"]["want_response_signed"] = "false"
SAML_CONFIG["service"]["sp"]["want_assertions_signed"] = "0"
