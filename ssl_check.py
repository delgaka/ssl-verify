#!/usr/bin/env python3
import socket
import ssl
import sys
import json
from datetime import datetime
import pytz
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import pandas as pd


def ler_arquivo(arquivo):
    try:
        with open("./".join(arquivo), "r") as f:
            return [linha.strip() for linha in f.readlines()]
    except Exception as e:
        print("Erro ao abrir arquivo:", e)
        return []


def get_certificate(hostname, port=443, verify=True):
    context = (
        ssl.create_default_context() if verify else ssl._create_unverified_context()
    )
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    try:
        conn.settimeout(5)
        conn.connect((hostname, port))
        der_cert = conn.getpeercert(binary_form=True)
        conn.close()
        return der_cert
    except Exception as e:
        return {"hostname": hostname, "error": str(e)}


def parse_cert(der_cert, hostname, note=None):
    cert = x509.load_der_x509_certificate(der_cert, default_backend())

    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except IndexError:
        cn = ""

    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    begin = cert.not_valid_before_utc
    end = cert.not_valid_after_utc
    now = datetime.now(pytz.UTC)

    try:
        issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[
            0
        ].value
    except IndexError:
        issuer = ""

    if now < begin:
        validity = "not yet valid"
    elif now > end:
        validity = "expired"
    else:
        validity = "valid"

    return {
        "hostname": hostname,
        "common_name": cn,
        "subject_alt_names": sans,
        "valid_from": begin.isoformat(),
        "valid_to": end.isoformat(),
        "issuer": issuer,
        "validity_status": validity,
        "note": note or "",
    }


if len(sys.argv) < 2:
    print("Uso: python ssl_check_json.py hosts.txt")
    sys.exit(1)

hosts = ler_arquivo(sys.argv[1:])
resultados = []

for host in hosts:
    cert_bin = get_certificate(host)
    if isinstance(cert_bin, dict) and "error" in cert_bin:
        cert_bin_unverified = get_certificate(host, verify=False)
        if isinstance(cert_bin_unverified, dict) and "error" in cert_bin_unverified:
            resultados.append(cert_bin)  # mantém erro original
        else:
            parsed = parse_cert(
                cert_bin_unverified,
                host,
                note="certificate retrieved without verification",
            )
            resultados.append(parsed)
    else:
        resultados.append(parse_cert(cert_bin, host))

# Salvar JSON
with open("certificados_resultado.json", "w") as f:
    json.dump(resultados, f, indent=2)

# Salvar CSV
df = pd.json_normalize(resultados)
df.to_csv("certificados_resultado.csv", index=False)

print("Resultados salvos em:")
print(" - certificados_resultado.json")
print(" - certificados_resultado.csv")
