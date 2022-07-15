from os import path

import saml2
from saml2 import attributemaps

DEFAULT_ATTRIBUTEMAPS = path.dirname(attributemaps.__file__)

BASE_URL = 'http://test.localhost/'
SAML2DIR = path.dirname(__file__)

SAML_CONFIG = {
    # full path to the xmlsec1 binary programm
    'xmlsec_binary': '/usr/bin/xmlsec1',
    # your entity id, usually your subdomain plus the url to the metadata view
    'entityid': '%ssaml2-metadata' % BASE_URL,
    # directory with attribute mapping
    'attribute_map_dir': DEFAULT_ATTRIBUTEMAPS,
    'allow_unknown_attributes': True,  # Allow eduidIdPCredentialsUsed
    # this block states what services we provide
    'service': {
        # we are just a lonely SP
        'sp': {
            'name': 'Example SP',
            'endpoints': {
                # url and binding to the assetion consumer service view
                # do not change the binding or service name
                'assertion_consumer_service': [
                    ('%ssaml2-acs' % BASE_URL, saml2.BINDING_HTTP_POST),
                ],
                # url and binding to the single logout service view
                # do not change the binding or service name
                'single_logout_service': [
                    ('%ssaml2-ls' % BASE_URL, saml2.BINDING_HTTP_REDIRECT),
                ],
            },
            # Do not check for signature during tests
            'want_response_signed': False,
            # # This is commented to be compatible with simplesamlphp
            # # attributes that this project need to identify a user
            # 'required_attributes': ['uid'],
            #
            # # attributes that may be useful to have but not required
            # 'optional_attributes': ['eduPersonAffiliation'],
            # in this section the list of IdPs we talk to are defined
            'idp': {
                # we do not need a WAYF service since there is
                # only an IdP defined here. This IdP should be
                # present in our metadata
                # the keys of this dictionary are entity ids
                'https://idp.example.com/simplesaml/saml2/idp/metadata.php': {
                    'single_sign_on_service': {
                        saml2.BINDING_HTTP_REDIRECT: 'https://idp.example.com/simplesaml/saml2/idp/SSOService.php',
                    },
                    'single_logout_service': {
                        saml2.BINDING_HTTP_REDIRECT: 'https://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php',
                    },
                },
            },
        },
    },
    "discovery_response": ['%sdiscovery-response' % BASE_URL],
    # where the remote metadata is stored
    'metadata': {
        'local': [path.join(SAML2DIR, 'remote_metadata.xml')],
    },
    # set to 1 to output debugging information
    'debug': 1,
    # certificate
    'key_file': path.join("%s%s" % (SAML2DIR, "/certs"), 'test_sp.key'),  # private part
    'cert_file': path.join("%s%s" % (SAML2DIR, "/certs"), 'test_sp.crt'),  # public part
    'encryption_keypairs': [
        {
            'key_file': path.join("%s%s" % (SAML2DIR, "/certs"), 'test_sp.key'),  # private part
            'cert_file': path.join("%s%s" % (SAML2DIR, "/certs"), 'test_sp.crt'),  # public part
        }
    ],
    # own metadata settings
    'contact_person': [
        {
            'given_name': 'Sysadmin',
            'sur_name': '',
            'company': 'Example CO',
            'email_address': 'sysadmin@example.com',
            'contact_type': 'technical',
        },
        {
            'given_name': 'Admin',
            'sur_name': 'CEO',
            'company': 'Example CO',
            'email_address': 'admin@example.com',
            'contact_type': 'administrative',
        },
    ],
    # you can set multilanguage information here
    'organization': {
        'name': [('Example CO', 'es'), ('Example CO', 'en')],
        'display_name': [('Example', 'es'), ('Example', 'en')],
        'url': [('http://www.example.com', 'es'), ('http://www.example.com', 'en')],
    },
}
