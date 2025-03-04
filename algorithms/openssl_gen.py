from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime, timedelta

# Generate RSA Private Key
private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

# Generate Self-Signed Certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Secure App"),
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
])

cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
    private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
    datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=365)).add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(
    private_key, hashes.SHA256())

# Save Private Key
with open("server_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))

# Save Certificate
with open("server_cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("SSL Certificate and Key generated successfully!")
