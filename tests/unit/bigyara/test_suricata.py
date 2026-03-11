# import unittest

# from azul_plugin_retrohunt.bigyara.suricata_parse import (
#     _handle_escapes,
#     _ips_to_atoms,
#     _pcre_atoms,
#     parse_suricata_rules,
# )

# FUTURE suricata - implement

# class TestSuricataParsing(unittest.TestCase):
#     def test_pcre(self):
#         """
#         Ignores flags
#         """
#         self.assertEqual(_pcre_atoms(r"/^PASS\s*\n/smi"), [b"PASS"])
#         # too small
#         self.assertEqual(_pcre_atoms(r"/^PW\s*\n/smi"), [])
#         self.assertEqual(_pcre_atoms(r"/^\W{3,5}\s*\n/smi"), [])
#         self.assertEqual(_pcre_atoms(r"/\Wfrom=[^\x3b&\n]{100}/"), [b"from="])
#         # taken from distribution's suricata rules.. note the re syntax issues
#         self.assertEqual(
#             _pcre_atoms(r"/awstats.pl?[^\r\n]*logfile=\x7C/Ui"),
#             [
#                 b"awstats",
#                 b"logfile=|",
#             ],
#         )

#     def test_ipaddress(self):
#         self.assertEqual(_ips_to_atoms("alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS"), [])
#         self.assertEqual(_ips_to_atoms("alert icmp any any <> any $HTTP_PORTS"), [])
#         self.assertEqual(_ips_to_atoms("alert icmp any 123 <> any $HTTP_PORTS"), [])
#         self.assertEqual(_ips_to_atoms("alert udp 211.123.123.112 any <> any any"), [b"\xd3{{p"])
#         self.assertEqual(
#             _ips_to_atoms("alert tcp 211.123.123.112 any -> 211.123.123.111 any"), [b"\xd3{{p", b"\xd3{{o"]
#         )
#         # FUTURE: cidr support

#     def test_content(self):
#         self.assertEqual(_handle_escapes("|01 00 01 00|"), b"\x01\x00\x01\x00")
#         self.assertEqual(_handle_escapes("BattleMail"), b"BattleMail")
#         self.assertEqual(_handle_escapes("\\;Battle|7c 7c|Mail"), b";Battle||Mail")

#     def test_parser(self):
#         rules, _ = parse_snort_rules(
#             r'alert tcp 211.123.123.112 any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Silly Test"; flow:to_server,established; content:"/Admin/Login.php"; pcre:"/^Authorization\s*Basic/sm"; classtype:web-application-attack; sid:1; rev:1;)',
#             lambda *a: None,
#         )
#         self.assertDictEqual(rules, {"1:Silly Test": [b"/Admin/Login.php", b"Authorization", b"Basic", b"\xd3{{p"]})
