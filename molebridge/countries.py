"""Country names to ISO 3166-1 alpha-2 codes, for flags.

Native catalogues carry a code (Mullvad's and NordVPN's location codes, PIA's
region country). gluetun's server list names countries in English only, so
the panel looks the name up here. An unknown name has no flag; nothing else
depends on it.
"""
from __future__ import annotations

_CODES = '''
AD Andorra|AE United Arab Emirates;UAE|AF Afghanistan|AL Albania|AM Armenia|AO Angola|AR Argentina
AT Austria|AU Australia|AZ Azerbaijan|BA Bosnia and Herzegovina;Bosnia|BD Bangladesh|BE Belgium
BG Bulgaria|BH Bahrain|BM Bermuda|BN Brunei|BO Bolivia|BR Brazil|BS Bahamas|BT Bhutan|BY Belarus
BZ Belize|CA Canada|CH Switzerland|CI Ivory Coast;Cote d'Ivoire|CL Chile|CN China|CO Colombia
CR Costa Rica|CY Cyprus|CZ Czech Republic;Czechia|DE Germany|DK Denmark|DO Dominican Republic
DZ Algeria|EC Ecuador|EE Estonia|EG Egypt|ES Spain|ET Ethiopia|FI Finland|FR France|GB United Kingdom;UK;Great Britain
GE Georgia|GH Ghana|GL Greenland|GR Greece|GT Guatemala|GU Guam|HK Hong Kong|HN Honduras|HR Croatia
HU Hungary|ID Indonesia|IE Ireland|IL Israel|IM Isle of Man|IN India|IQ Iraq|IS Iceland|IT Italy
JE Jersey|JM Jamaica|JO Jordan|JP Japan|KE Kenya|KG Kyrgyzstan|KH Cambodia|KR South Korea;Korea
KW Kuwait|KY Cayman Islands|KZ Kazakhstan|LA Laos|LB Lebanon|LI Liechtenstein|LK Sri Lanka
LT Lithuania|LU Luxembourg|LV Latvia|LY Libya|MA Morocco|MC Monaco|MD Moldova|ME Montenegro
MK North Macedonia;Macedonia|MM Myanmar|MN Mongolia|MO Macau;Macao|MT Malta|MU Mauritius|MV Maldives
MX Mexico|MY Malaysia|MZ Mozambique|NG Nigeria|NI Nicaragua|NL Netherlands|NO Norway|NP Nepal
NZ New Zealand|OM Oman|PA Panama|PE Peru|PG Papua New Guinea|PH Philippines|PK Pakistan|PL Poland
PR Puerto Rico|PT Portugal|PY Paraguay|QA Qatar|RO Romania|RS Serbia|RU Russia|RW Rwanda
SA Saudi Arabia|SE Sweden|SG Singapore|SI Slovenia|SK Slovakia|SN Senegal|SV El Salvador|SY Syria
TH Thailand|TN Tunisia|TR Turkey;Turkiye|TT Trinidad and Tobago|TW Taiwan|TZ Tanzania|UA Ukraine
UG Uganda|US United States;USA;United States of America|UY Uruguay|UZ Uzbekistan|VE Venezuela
VN Vietnam;Viet Nam|ZA South Africa|ZW Zimbabwe
'''
NAME_TO_CODE = {name.strip().lower(): code
                for entry in _CODES.replace('\n', '|').split('|') if entry.strip()
                for code, _, names in [entry.strip().partition(' ')]
                for name in names.split(';')}


def code_for(name):
    """'United States' -> 'US'; None for a name not in the table."""
    return NAME_TO_CODE.get(name.strip().lower()) if isinstance(name, str) else None
