import os
import tempfile
import subprocess
import shutil
import zipfile
from io import BytesIO
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
from cryptography import x509
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

UPLOAD_FOLDER = tempfile.mkdtemp()
OUTPUT_FOLDER = tempfile.mkdtemp()


def extract_root_cert(ca_chain_content):
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


def get_cert_info(cert_pem):
    """Get certificate subject and issuer info."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        # Handle both old and new cryptography API versions
        try:
            not_before = cert.not_valid_before_utc.isoformat()
            not_after = cert.not_valid_after_utc.isoformat()
        except AttributeError:
            not_before = cert.not_valid_before.isoformat()
            not_after = cert.not_valid_after.isoformat()

        return {
            'subject': cert.subject.rfc4514_string(),
            'issuer': cert.issuer.rfc4514_string(),
            'not_before': not_before,
            'not_after': not_after
        }
    except Exception as e:
        return {'error': str(e)}


def generate_stores(ca_chain, bundle, key, alias, truststore_password, keystore_password):
    """Generate truststore.jks and keystore.jks from certificates."""
    work_dir = tempfile.mkdtemp()
    results = {'success': False, 'files': {}, 'errors': [], 'info': []}

    try:
        # Save files to work directory
        ca_chain_path = os.path.join(work_dir, 'CA_chain')
        bundle_path = os.path.join(work_dir, 'bundle')
        key_path = os.path.join(work_dir, 'key')
        truststore_path = os.path.join(work_dir, 'truststore.jks')
        keystore_p12_path = os.path.join(work_dir, 'keystore.p12')
        keystore_jks_path = os.path.join(work_dir, 'keystore.jks')

        with open(ca_chain_path, 'w') as f:
            f.write(ca_chain)
        with open(bundle_path, 'w') as f:
            f.write(bundle)
        with open(key_path, 'w') as f:
            f.write(key)

        # Extract all certificates from CA chain
        certs = []
        current_cert = []
        in_cert = False

        for line in ca_chain.split('\n'):
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

        if not certs:
            results['errors'].append("Could not extract certificates from CA chain")
            return results

        # Step 1: Create truststore with ALL CA certificates
        for i, cert_pem in enumerate(certs):
            cert_temp_path = os.path.join(work_dir, f'ca_{i}.pem')
            with open(cert_temp_path, 'w') as f:
                f.write(cert_pem)

            cmd_truststore = [
                'keytool', '-import', '-file', cert_temp_path,
                '-alias', f'{alias}-ca-{i}',
                '-keystore', truststore_path,
                '-storepass', truststore_password,
                '-noprompt'
            ]
            result = subprocess.run(cmd_truststore, capture_output=True, text=True)
            if result.returncode != 0:
                results['errors'].append(f"Truststore creation failed for cert {i}: {result.stderr}")
                return results

        results['info'].append(f"Truststore created successfully with {len(certs)} CA certificates")

        # Step 2: Create .p12 keystore (bundle contains cert + intermediates)
        cmd_p12 = [
            'openssl', 'pkcs12', '-export',
            '-in', bundle_path,
            '-inkey', key_path,
            '-name', alias,
            '-out', keystore_p12_path,
            '-passout', f'pass:{keystore_password}'
        ]
        result = subprocess.run(cmd_p12, capture_output=True, text=True)
        if result.returncode != 0:
            results['errors'].append(f"P12 creation failed: {result.stderr}")
            return results
        results['info'].append("P12 keystore created successfully")

        # Step 3: Convert .p12 to .jks
        cmd_jks = [
            'keytool', '-importkeystore',
            '-srckeystore', keystore_p12_path,
            '-srcstoretype', 'pkcs12',
            '-srcstorepass', keystore_password,
            '-destkeystore', keystore_jks_path,
            '-deststoretype', 'jks',
            '-deststorepass', keystore_password,
            '-alias', alias
        ]
        result = subprocess.run(cmd_jks, capture_output=True, text=True)
        if result.returncode != 0:
            results['errors'].append(f"JKS conversion failed: {result.stderr}")
            return results
        results['info'].append("JKS keystore created successfully")

        # Read generated files
        with open(truststore_path, 'rb') as f:
            results['files']['truststore.jks'] = f.read()
        with open(keystore_jks_path, 'rb') as f:
            results['files']['keystore.jks'] = f.read()
        with open(keystore_p12_path, 'rb') as f:
            results['files']['keystore.p12'] = f.read()

        # Also save PEM files for openssl testing
        results['pem_files'] = {
            'ca_chain': ca_chain,
            'bundle': bundle,
            'key': key
        }
        results['passwords'] = {
            'truststore': truststore_password,
            'keystore': keystore_password
        }

        results['success'] = True

    except Exception as e:
        results['errors'].append(str(e))
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    return results


def generate_properties_file(bootstrap_server, truststore_path, keystore_path, truststore_password, keystore_password):
    """Generate client-ssl.properties content."""
    return f"""# Kafka SSL Configuration
# Generated by Kafstore

security.protocol=SSL
ssl.truststore.location={truststore_path}
ssl.truststore.password={truststore_password}
ssl.keystore.location={keystore_path}
ssl.keystore.password={keystore_password}
ssl.key.password={keystore_password}
ssl.endpoint.identification.algorithm=

# Bootstrap server
bootstrap.servers={bootstrap_server}
"""


def test_kafka_connection(bootstrap_server, properties_content):
    """Test Kafka connection using kafka-topics.sh or kafka-python."""
    work_dir = tempfile.mkdtemp()
    try:
        from kafka import KafkaAdminClient
        from kafka.errors import KafkaError

        # Parse properties
        props = {}
        for line in properties_content.split('\n'):
            if '=' in line and not line.strip().startswith('#'):
                key, value = line.split('=', 1)
                props[key.strip()] = value.strip()

        # This is a simplified test - in production you'd configure SSL properly
        admin = KafkaAdminClient(
            bootstrap_servers=bootstrap_server,
            security_protocol='SSL',
            ssl_check_hostname=False,
            ssl_cafile=props.get('ssl.truststore.location'),
            request_timeout_ms=10000
        )
        topics = admin.list_topics()
        admin.close()
        return {'success': True, 'topics': topics}
    except Exception as e:
        return {'success': False, 'error': str(e)}
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/generate', methods=['POST'])
def generate():
    """Generate keystores and truststore from uploaded certificates."""
    try:
        # Get form data
        alias = request.form.get('alias', 'kafka-client')
        truststore_password = request.form.get('truststore_password', 'changeit')
        keystore_password = request.form.get('keystore_password', 'changeit')
        bootstrap = request.form.get('bootstrap', 'your-kafka-broker:443')

        # Get uploaded files (only 3 needed now)
        ca_chain = request.files.get('ca_chain')
        bundle = request.files.get('bundle')
        key = request.files.get('key')

        if not all([ca_chain, bundle, key]):
            return jsonify({'success': False, 'error': 'All 3 certificate files are required (CA chain, bundle, key)'}), 400

        # Read file contents
        ca_chain_content = ca_chain.read().decode('utf-8')
        bundle_content = bundle.read().decode('utf-8')
        key_content = key.read().decode('utf-8')

        # Generate stores
        result = generate_stores(
            ca_chain_content, bundle_content, key_content,
            alias, truststore_password, keystore_password
        )

        if not result['success']:
            return jsonify(result), 400

        # Generate properties file
        properties_content = generate_properties_file(
            bootstrap,
            '/absolute/path/to/truststore.jks',
            '/absolute/path/to/keystore.jks',
            truststore_password,
            keystore_password
        )
        result['files']['client-ssl.properties'] = properties_content.encode('utf-8')

        # Create ZIP file
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for filename, content in result['files'].items():
                zip_file.writestr(filename, content)

        zip_buffer.seek(0)

        return send_file(
            zip_buffer,
            mimetype='application/zip',
            as_attachment=True,
            download_name='kafka-ssl-config.zip'
        )

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/analyze', methods=['POST'])
def analyze_cert():
    """Analyze uploaded certificate and return info."""
    try:
        cert_file = request.files.get('cert')
        if not cert_file:
            return jsonify({'success': False, 'error': 'No certificate provided'}), 400

        cert_content = cert_file.read().decode('utf-8')

        # If it's a chain, analyze all certs
        certs = []
        current_cert = []
        in_cert = False

        for line in cert_content.split('\n'):
            if '-----BEGIN CERTIFICATE-----' in line:
                in_cert = True
                current_cert = [line]
            elif '-----END CERTIFICATE-----' in line:
                current_cert.append(line)
                certs.append('\n'.join(current_cert))
                in_cert = False
            elif in_cert:
                current_cert.append(line)

        results = []
        for i, cert_pem in enumerate(certs):
            info = get_cert_info(cert_pem)
            info['index'] = i
            info['is_root'] = i == 0
            results.append(info)

        return jsonify({'success': True, 'certificates': results})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/test-kafka', methods=['POST'])
def test_kafka():
    """Test Kafka connection with uploaded or generated stores."""
    work_dir = tempfile.mkdtemp()
    try:
        bootstrap = request.form.get('bootstrap')
        password = request.form.get('password', 'changeit')

        if not bootstrap:
            return jsonify({'success': False, 'error': 'Bootstrap server is required'}), 400

        # Check if stores are uploaded directly
        truststore_file = request.files.get('truststore')
        keystore_file = request.files.get('keystore')

        # Or use certificates to generate stores on the fly
        ca_chain = request.files.get('ca_chain')
        bundle = request.files.get('bundle')
        key = request.files.get('key')

        truststore_path = os.path.join(work_dir, 'truststore.jks')
        keystore_path = os.path.join(work_dir, 'keystore.jks')
        properties_path = os.path.join(work_dir, 'client-ssl.properties')

        # PEM files for openssl testing
        ca_chain_content = None
        bundle_content = None
        key_content = None

        # Option 1: Use uploaded JKS files directly
        if truststore_file and keystore_file:
            with open(truststore_path, 'wb') as f:
                f.write(truststore_file.read())
            with open(keystore_path, 'wb') as f:
                f.write(keystore_file.read())
        # Option 2: Generate stores from certificates
        elif all([ca_chain, bundle, key]):
            ca_chain_content = ca_chain.read().decode('utf-8')
            bundle_content = bundle.read().decode('utf-8')
            key_content = key.read().decode('utf-8')

            result = generate_stores(
                ca_chain_content, bundle_content, key_content,
                'kafka-test', password, password
            )

            if not result['success']:
                return jsonify({'success': False, 'error': 'Failed to generate stores', 'details': result['errors']}), 400

            with open(truststore_path, 'wb') as f:
                f.write(result['files']['truststore.jks'])
            with open(keystore_path, 'wb') as f:
                f.write(result['files']['keystore.jks'])
        else:
            return jsonify({
                'success': False,
                'error': 'Please provide either JKS files (truststore + keystore) or certificate files (ca_chain, bundle, key)'
            }), 400

        # Create properties file
        properties_content = f"""security.protocol=SSL
ssl.truststore.location={truststore_path}
ssl.truststore.password={password}
ssl.keystore.location={keystore_path}
ssl.keystore.password={password}
ssl.key.password={password}
ssl.endpoint.identification.algorithm=
"""
        with open(properties_path, 'w') as f:
            f.write(properties_content)

        # Test connection using kafka-topics.sh (if available) or openssl
        # First try kafka-topics.sh
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
                return jsonify({
                    'success': True,
                    'message': 'Connection successful!',
                    'topics': topics,
                    'topics_count': len(topics)
                })
            else:
                return jsonify({
                    'success': False,
                    'error': 'Kafka connection failed',
                    'details': result.stderr or result.stdout
                })

        # Fallback: Test connection using Java with the generated JKS files
        host, port = bootstrap.split(':') if ':' in bootstrap else (bootstrap, '443')

        # Create a simple Java SSL test program
        java_test_code = f'''
import javax.net.ssl.*;
import java.io.*;
import java.security.*;

public class SSLTest {{
    public static void main(String[] args) {{
        System.setProperty("javax.net.ssl.trustStore", "{truststore_path}");
        System.setProperty("javax.net.ssl.trustStorePassword", "{password}");
        System.setProperty("javax.net.ssl.keyStore", "{keystore_path}");
        System.setProperty("javax.net.ssl.keyStorePassword", "{password}");

        try {{
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) factory.createSocket("{host}", {port});
            socket.startHandshake();

            System.out.println("SUCCESS: SSL handshake completed");
            System.out.println("Protocol: " + socket.getSession().getProtocol());
            System.out.println("CipherSuite: " + socket.getSession().getCipherSuite());

            socket.close();
        }} catch (Exception e) {{
            System.err.println("ERROR: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }}
    }}
}}
'''
        java_file_path = os.path.join(work_dir, 'SSLTest.java')
        with open(java_file_path, 'w') as f:
            f.write(java_test_code)

        # Compile and run the Java test
        try:
            # Compile
            compile_result = subprocess.run(
                ['javac', java_file_path],
                capture_output=True,
                text=True,
                cwd=work_dir,
                timeout=10
            )

            if compile_result.returncode != 0:
                return jsonify({
                    'success': False,
                    'error': 'Failed to compile SSL test',
                    'details': compile_result.stderr
                }), 500

            # Run
            run_result = subprocess.run(
                ['java', '-cp', work_dir, 'SSLTest'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if run_result.returncode == 0:
                return jsonify({
                    'success': True,
                    'message': f'mTLS connection successful to {host}:{port}',
                    'details': 'Certificate verification passed using generated JKS files',
                    'ssl_info': run_result.stdout
                })
            else:
                error_msg = run_result.stderr or run_result.stdout
                return jsonify({
                    'success': False,
                    'error': f'SSL connection failed to {host}:{port}',
                    'details': error_msg[:800]
                })

        except subprocess.TimeoutExpired:
            return jsonify({
                'success': False,
                'error': f'Connection timeout to {host}:{port}',
                'details': 'The server did not respond within 30 seconds'
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': 'Test execution failed',
                'details': str(e)
            }), 500

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
