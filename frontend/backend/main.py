"""
FastAPI backend for mTLS Configurator
Handles JKS/P12 generation using system keytool and openssl
"""
import os
import tempfile
import subprocess
import shutil
import zipfile
from io import BytesIO
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from cryptography import x509
from cryptography.hazmat.backends import default_backend

app = FastAPI(title="mTLS Configurator API", version="1.0.0")

# CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CertificateInfo(BaseModel):
    index: int
    subject: str
    issuer: str
    not_before: str
    not_after: str
    is_root: bool


class AnalyzeResponse(BaseModel):
    success: bool
    certificates: list[CertificateInfo]
    error: Optional[str] = None


class TestResult(BaseModel):
    success: bool
    message: str
    details: Optional[str] = None
    topics: Optional[list[str]] = None


def extract_root_cert(ca_chain_content: str) -> str:
    """Extract the root certificate (first one) from CA chain."""
    certs = []
    current_cert = []
    in_cert = False

    for line in ca_chain_content.split('\n'):
        if '-----BEGIN CERTIFICATE-----' in line:
            in_cert = True
            current_cert = [line]
        elif '-----END CERTIFICATE-----' in line:
            current_cert.append(line)
            certs.append('\n'.join(current_cert))
            in_cert = False
            current_cert = []
        elif in_cert:
            current_cert.append(line)

    return certs[0] if certs else None


def get_cert_info(cert_pem: str, index: int) -> CertificateInfo:
    """Get certificate subject and issuer info."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()

    return CertificateInfo(
        index=index,
        subject=subject,
        issuer=issuer,
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        is_root=(subject == issuer)
    )


def parse_cert_chain(content: str) -> list[str]:
    """Parse PEM certificate chain into individual certificates."""
    certs = []
    current_cert = []
    in_cert = False

    for line in content.split('\n'):
        if '-----BEGIN CERTIFICATE-----' in line:
            in_cert = True
            current_cert = [line]
        elif '-----END CERTIFICATE-----' in line:
            current_cert.append(line)
            certs.append('\n'.join(current_cert))
            in_cert = False
        elif in_cert:
            current_cert.append(line)

    return certs


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "keytool": shutil.which("keytool") is not None}


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_certificate(cert: UploadFile = File(...)):
    """Analyze uploaded certificate and return info."""
    try:
        content = (await cert.read()).decode('utf-8')
        certs = parse_cert_chain(content)

        certificates = []
        for i, cert_pem in enumerate(certs):
            try:
                info = get_cert_info(cert_pem, i)
                certificates.append(info)
            except Exception as e:
                pass

        return AnalyzeResponse(success=True, certificates=certificates)
    except Exception as e:
        return AnalyzeResponse(success=False, certificates=[], error=str(e))


@app.post("/api/generate")
async def generate_stores(
    ca_chain: UploadFile = File(...),
    cert: UploadFile = File(...),
    key: UploadFile = File(...),
    bundle: UploadFile = File(...),
    alias: str = Form("kafka-client"),
    password: str = Form("changeit"),
    bootstrap: str = Form("")
):
    """Generate truststore.jks and keystore.p12 from certificates."""
    work_dir = tempfile.mkdtemp()

    try:
        # Read uploaded files
        ca_chain_content = (await ca_chain.read()).decode('utf-8')
        cert_content = (await cert.read()).decode('utf-8')
        key_content = (await key.read()).decode('utf-8')
        bundle_content = (await bundle.read()).decode('utf-8')

        # Extract root certificate
        root_cert = extract_root_cert(ca_chain_content)
        if not root_cert:
            raise HTTPException(status_code=400, detail="Could not extract root certificate from CA chain")

        # Save files to work directory
        ca_root_path = os.path.join(work_dir, 'CA_root.pem')
        cert_path = os.path.join(work_dir, 'cert.pem')
        key_path = os.path.join(work_dir, 'key.pem')
        bundle_path = os.path.join(work_dir, 'bundle.pem')
        truststore_path = os.path.join(work_dir, 'truststore.jks')
        keystore_p12_path = os.path.join(work_dir, 'keystore.p12')

        with open(ca_root_path, 'w') as f:
            f.write(root_cert)
        with open(cert_path, 'w') as f:
            f.write(cert_content)
        with open(key_path, 'w') as f:
            f.write(key_content)
        with open(bundle_path, 'w') as f:
            f.write(bundle_content)

        # Step 1: Create truststore.jks
        cmd_truststore = [
            'keytool', '-import', '-file', ca_root_path,
            '-alias', f'{alias}-ca',
            '-keystore', truststore_path,
            '-storepass', password,
            '-noprompt'
        ]
        result = subprocess.run(cmd_truststore, capture_output=True, text=True)
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Truststore creation failed: {result.stderr}")

        # Step 2: Create keystore.p12
        cmd_p12 = [
            'openssl', 'pkcs12', '-export',
            '-in', cert_path,
            '-inkey', key_path,
            '-certfile', bundle_path,
            '-name', alias,
            '-out', keystore_p12_path,
            '-passout', f'pass:{password}'
        ]
        result = subprocess.run(cmd_p12, capture_output=True, text=True)
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Keystore creation failed: {result.stderr}")

        # Generate properties file
        properties_content = f"""# Kafka SSL Configuration
# Generated by mTLS Configurator

security.protocol=SSL

ssl.truststore.location=/path/to/truststore.jks
ssl.truststore.password={password}

ssl.keystore.location=/path/to/keystore.p12
ssl.keystore.password={password}
ssl.keystore.type=PKCS12
ssl.key.password={password}

ssl.endpoint.identification.algorithm=

bootstrap.servers={bootstrap}
"""

        # Create ZIP file
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.write(truststore_path, 'truststore.jks')
            zip_file.write(keystore_p12_path, 'keystore.p12')
            zip_file.writestr('client-ssl.properties', properties_content)
            zip_file.writestr('CA_root.pem', root_cert)

        zip_buffer.seek(0)

        return StreamingResponse(
            zip_buffer,
            media_type='application/zip',
            headers={'Content-Disposition': 'attachment; filename=kafka-ssl-config.zip'}
        )

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


@app.post("/api/test-connection", response_model=TestResult)
async def test_kafka_connection(
    truststore: UploadFile = File(...),
    keystore: UploadFile = File(...),
    password: str = Form("changeit"),
    bootstrap: str = Form(...)
):
    """Test Kafka connection using uploaded stores."""
    work_dir = tempfile.mkdtemp()

    try:
        # Save uploaded files
        truststore_path = os.path.join(work_dir, 'truststore.jks')
        keystore_path = os.path.join(work_dir, 'keystore.p12')
        properties_path = os.path.join(work_dir, 'client-ssl.properties')

        with open(truststore_path, 'wb') as f:
            f.write(await truststore.read())
        with open(keystore_path, 'wb') as f:
            f.write(await keystore.read())

        # Create properties file
        properties_content = f"""security.protocol=SSL
ssl.truststore.location={truststore_path}
ssl.truststore.password={password}
ssl.keystore.location={keystore_path}
ssl.keystore.password={password}
ssl.keystore.type=PKCS12
ssl.key.password={password}
ssl.endpoint.identification.algorithm=
"""
        with open(properties_path, 'w') as f:
            f.write(properties_content)

        # Try kafka-topics.sh first
        kafka_bin = shutil.which('kafka-topics.sh') or shutil.which('kafka-topics')

        if kafka_bin:
            cmd = [
                kafka_bin, '--list',
                '--command-config', properties_path,
                '--bootstrap-server', bootstrap
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                topics = [t.strip() for t in result.stdout.strip().split('\n') if t.strip()]
                return TestResult(
                    success=True,
                    message=f"Connection successful! Found {len(topics)} topics.",
                    topics=topics
                )
            else:
                return TestResult(
                    success=False,
                    message="Kafka connection failed",
                    details=result.stderr or result.stdout
                )

        # Fallback: Test SSL handshake with openssl
        host, port = bootstrap.split(':') if ':' in bootstrap else (bootstrap, '443')

        cmd_ssl = ['openssl', 's_client', '-connect', f'{host}:{port}', '-brief']

        try:
            result = subprocess.run(
                cmd_ssl,
                capture_output=True,
                text=True,
                timeout=10,
                input=''
            )

            if 'CONNECTED' in result.stdout or 'CONNECTED' in result.stderr:
                return TestResult(
                    success=True,
                    message=f"SSL handshake successful with {host}:{port}",
                    details="Kafka CLI not available - performed basic SSL connectivity test only"
                )
            else:
                return TestResult(
                    success=False,
                    message=f"Cannot establish SSL connection to {host}:{port}",
                    details=result.stderr[:500] if result.stderr else "Unknown error"
                )
        except subprocess.TimeoutExpired:
            return TestResult(
                success=False,
                message=f"Connection timeout to {host}:{port}",
                details="The server did not respond within 10 seconds"
            )

    except Exception as e:
        return TestResult(success=False, message="Test failed", details=str(e))
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
