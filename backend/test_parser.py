from parser.email_parser import parse_email
from parser.header_analyzer import analyze_headers


email_data = parse_email("samples/test.eml")

header_analysis = analyze_headers(email_data)


print("\n==============================")
print("       EMAIL FORENSICS")
print("==============================")

print("\n--- EMAIL ---")

print("From:", email_data["from"])
print("To:", email_data["to"])
print("Subject:", email_data["subject"])
print("Reply-To:", email_data["reply_to"])
print("Return-Path:", email_data["return_path"])

print("\n--- AUTHENTICATION ---")

print("SPF:", header_analysis["authentication"]["spf"])
print("DKIM:", header_analysis["authentication"]["dkim"])
print("DMARC:", header_analysis["authentication"]["dmarc"])

print("\n--- SENDER WARNINGS ---")

for warning in header_analysis["sender_warnings"]:
    print("⚠", warning)

print("\n--- RECEIVED ROUTE ---")

print("Number of hops:", header_analysis["received_hops"])

print("IPs found in Received headers:")

for ip in header_analysis["received_ips"]:
    print("•", ip)

print("\n--- BODY IOCs ---")

print("URLs:", email_data["urls"])
print("IPs:", email_data["ips"])
print("\n--- SECURITY INDICATORS ---")

for indicator in header_analysis["indicators"]:
    print("⚠", indicator)