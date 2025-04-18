"""Imports"""
import argparse
import socket  # Added explicitly for IP validation
from scapy.all import send
from scapy.layers.inet import IP, UDP
from scapy.asn1.asn1 import ASN1_OID, ASN1_STRING
from scapy.layers.snmp import SNMP, SNMPtrapv2, SNMPvarbind


def main():
    """Main function to parse arguments and send an SNMPv3 Trap."""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Send an SNMPv3 Trap")
    parser.add_argument("--target_ip", required=True, help="Receiver's IP address")
    parser.add_argument("--target_port", type=int, default=162, help="Receiver's port (default: 162)")
    parser.add_argument("--username", required=True, help="SNMPv3 username")
    parser.add_argument("--auth_protocol", default="usmHMACMD5AuthProtocol", help="Authentication protocol (default: MD5)")
    parser.add_argument("--auth_key", required=True, help="Authentication key")
    parser.add_argument("--priv_protocol", default="usmDESPrivProtocol", help="Privacy protocol (default: DES)")
    parser.add_argument("--priv_key", required=True, help="Privacy key")
    parser.add_argument("--engine_id", required=True, help="SNMP engine ID")
    parser.add_argument("--oid", default="1.3.6.1.2.1.1.1.0", help="OID for the trap (default: 1.3.6.1.2.1.1.1.0)")
    parser.add_argument("--message", default="Test Trap Message", help="Trap message (default: 'Test Trap Message')")

    try:
        args = parser.parse_args()

        # Validate IP address
        try:
            socket.inet_aton(args.target_ip)
        except socket.error as exc:
            raise ValueError(f"Invalid IP address: {args.target_ip}") from exc

        # Define the trap content
        oid = ASN1_OID(args.oid)
        message = ASN1_STRING(args.message)

        # Build the SNMP Trap packet
        trap_packet = IP(dst=args.target_ip) / UDP(dport=args.target_port) / SNMP(
            version=3,
            community=args.username,
            PDU=SNMPtrapv2(
                varbindlist=[
                    SNMPvarbind(oid=oid, value=message)
                ]
            )
        )

        # Send the packet
        try:
            send(trap_packet)
            print("SNMPv3 Trap sent!")
        except PermissionError:
            print("Error: You need elevated privileges to send raw packets. Run with 'sudo'.")
        except (socket.error, ValueError) as e:
            print(f"An error occurred while sending the SNMP trap: {e}")

    except ValueError as ve:
        print(f"Value Error: {ve}")
    except argparse.ArgumentError as ae:
        print(f"Argument Error: {ae}")
    except (socket.error, PermissionError) as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
