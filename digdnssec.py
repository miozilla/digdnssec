import dns.resolver
import dns.dnssec
import dns.name
import dns.query
import dns.message

def check_dnssec(domain):
    print(f"[*] Checking DNSSEC for domain: {domain}")

    try:
        # Get DNSKEY
        dnskey_response = dns.resolver.resolve(domain, 'DNSKEY', raise_on_no_answer=False)
        if dnskey_response.rrset is None:
            print("[-] No DNSKEY records found — DNSSEC not enabled.")
            return

        print("[+] DNSKEY records found.")

        # Get RRSIG for DNSKEY
        rrsig_response = dns.resolver.resolve(domain, 'RRSIG', raise_on_no_answer=False)
        has_rrsig = any(rrsig.to_text().startswith('DNSKEY') for rrsig in rrsig_response)

        if has_rrsig:
            print("[+] RRSIG (signature) over DNSKEY found — DNSSEC is likely configured.")
        else:
            print("[-] No RRSIG records found — DNSSEC incomplete.")

    except dns.resolver.NoAnswer:
        print("[-] No answer received.")
    except dns.resolver.NXDOMAIN:
        print("[-] Domain does not exist.")
    except Exception as e:
        print(f"[!] Error: {e}")

# Example usage
check_dnssec("example.com")
