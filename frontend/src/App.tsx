import { useState, useCallback } from 'react';
import './App.css';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

interface CertificateInfo {
  index: number;
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  is_root: boolean;
}

interface FileState {
  caChain: File | null;
  cert: File | null;
  key: File | null;
  bundle: File | null;
}

interface TestFiles {
  truststore: File | null;
  keystore: File | null;
}

type Step = 'upload' | 'configure' | 'generate' | 'test';

function App() {
  const [currentStep, setCurrentStep] = useState<Step>('upload');
  const [files, setFiles] = useState<FileState>({
    caChain: null,
    cert: null,
    key: null,
    bundle: null,
  });
  const [testFiles, setTestFiles] = useState<TestFiles>({
    truststore: null,
    keystore: null,
  });

  const [alias, setAlias] = useState('kafka-client');
  const [password, setPassword] = useState('changeit');
  const [bootstrap, setBootstrap] = useState('');
  const [testBootstrap, setTestBootstrap] = useState('');
  const [testPassword, setTestPassword] = useState('changeit');

  const [caInfo, setCaInfo] = useState<CertificateInfo[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [notification, setNotification] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string; topics?: string[] } | null>(null);

  const showNotification = useCallback((type: 'success' | 'error' | 'info', message: string) => {
    setNotification({ type, message });
    setTimeout(() => setNotification(null), 5000);
  }, []);

  const handleFileChange = async (type: keyof FileState, file: File | null) => {
    setFiles(prev => ({ ...prev, [type]: file }));

    if (type === 'caChain' && file) {
      try {
        const formData = new FormData();
        formData.append('cert', file);

        const response = await fetch(`${API_URL}/api/analyze`, {
          method: 'POST',
          body: formData,
        });

        const data = await response.json();
        if (data.success) {
          setCaInfo(data.certificates);
        }
      } catch (error) {
        console.error('Failed to analyze certificate:', error);
      }
    }
  };

  const handleTestFileChange = (type: keyof TestFiles, file: File | null) => {
    setTestFiles(prev => ({ ...prev, [type]: file }));
  };

  const allFilesUploaded = files.caChain && files.cert && files.key && files.bundle;

  const handleGenerate = async () => {
    if (!allFilesUploaded) {
      showNotification('error', 'Please upload all certificate files');
      return;
    }

    setIsLoading(true);

    try {
      const formData = new FormData();
      formData.append('ca_chain', files.caChain!);
      formData.append('cert', files.cert!);
      formData.append('key', files.key!);
      formData.append('bundle', files.bundle!);
      formData.append('alias', alias);
      formData.append('password', password);
      formData.append('bootstrap', bootstrap);

      const response = await fetch(`${API_URL}/api/generate`, {
        method: 'POST',
        body: formData,
      });

      if (response.ok) {
        const blob = await response.blob();

        // Auto-download
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'kafka-ssl-config.zip';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();

        showNotification('success', 'Files generated successfully! Check your downloads.');
        setCurrentStep('test');
      } else {
        const error = await response.json();
        showNotification('error', error.detail || 'Generation failed');
      }
    } catch (error) {
      showNotification('error', `Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleTestConnection = async () => {
    if (!testFiles.truststore || !testFiles.keystore || !testBootstrap) {
      showNotification('error', 'Please upload truststore, keystore and enter bootstrap server');
      return;
    }

    setIsLoading(true);
    setTestResult(null);

    try {
      const formData = new FormData();
      formData.append('truststore', testFiles.truststore);
      formData.append('keystore', testFiles.keystore);
      formData.append('password', testPassword);
      formData.append('bootstrap', testBootstrap);

      const response = await fetch(`${API_URL}/api/test-connection`, {
        method: 'POST',
        body: formData,
      });

      const result = await response.json();
      setTestResult(result);

      if (result.success) {
        showNotification('success', result.message);
      } else {
        showNotification('error', result.message);
      }
    } catch (error) {
      showNotification('error', `Test failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setIsLoading(false);
    }
  };

  const steps = [
    { id: 'upload', label: 'Upload Certificates', icon: '1' },
    { id: 'configure', label: 'Configure', icon: '2' },
    { id: 'generate', label: 'Generate', icon: '3' },
    { id: 'test', label: 'Test Connection', icon: '4' },
  ];

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-content">
          <div className="logo">
            <div className="logo-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
              </svg>
            </div>
            <div className="logo-text">
              <h1>mTLS Configurator</h1>
              <span>Kafka SSL/TLS Setup Tool</span>
            </div>
          </div>
          <div className="security-badge">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="16" height="16">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            Secure Processing
          </div>
        </div>
      </header>

      {/* Progress Steps */}
      <div className="steps-container">
        <div className="steps">
          {steps.map((step, index) => (
            <div
              key={step.id}
              className={`step ${currentStep === step.id ? 'active' : ''} ${
                steps.findIndex(s => s.id === currentStep) > index ? 'completed' : ''
              }`}
              onClick={() => setCurrentStep(step.id as Step)}
            >
              <div className="step-icon">
                {steps.findIndex(s => s.id === currentStep) > index ? (
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" width="16" height="16">
                    <polyline points="20 6 9 17 4 12"/>
                  </svg>
                ) : (
                  step.icon
                )}
              </div>
              <span className="step-label">{step.label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Notification */}
      {notification && (
        <div className={`notification notification-${notification.type}`}>
          {notification.type === 'success' && '✓ '}
          {notification.type === 'error' && '✗ '}
          {notification.type === 'info' && 'ℹ '}
          {notification.message}
        </div>
      )}

      <main className="main-content">
        {/* Step 1: Upload */}
        {currentStep === 'upload' && (
          <div className="card fade-in">
            <div className="card-header">
              <h2>Upload Certificate Files</h2>
              <p>Upload the certificate files from your certificate authority</p>
            </div>

            <div className="upload-grid">
              {[
                { key: 'caChain', label: 'CA Chain', desc: 'CA_chain file', accept: '.pem,.crt,.cer' },
                { key: 'cert', label: 'Client Certificate', desc: 'cert file', accept: '.pem,.crt,.cer' },
                { key: 'key', label: 'Private Key', desc: 'key file', accept: '.pem,.key' },
                { key: 'bundle', label: 'Bundle', desc: 'bundle_cert_without_key', accept: '.pem,.crt,.cer' },
              ].map(({ key, label, desc, accept }) => (
                <div key={key} className={`upload-card ${files[key as keyof FileState] ? 'has-file' : ''}`}>
                  <input
                    type="file"
                    accept={accept}
                    onChange={(e) => handleFileChange(key as keyof FileState, e.target.files?.[0] || null)}
                    id={`file-${key}`}
                  />
                  <label htmlFor={`file-${key}`}>
                    <div className="upload-icon">
                      {files[key as keyof FileState] ? (
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <polyline points="20 6 9 17 4 12"/>
                        </svg>
                      ) : (
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                          <polyline points="17 8 12 3 7 8"/>
                          <line x1="12" y1="3" x2="12" y2="15"/>
                        </svg>
                      )}
                    </div>
                    <div className="upload-text">
                      <strong>{label}</strong>
                      <span>{files[key as keyof FileState]?.name || desc}</span>
                    </div>
                  </label>
                </div>
              ))}
            </div>

            {caInfo.length > 0 && (
              <div className="cert-analysis">
                <h3>Certificate Chain Analysis</h3>
                <div className="cert-list">
                  {caInfo.map((cert) => (
                    <div key={cert.index} className={`cert-item ${cert.is_root ? 'root' : ''}`}>
                      <div className="cert-badge">{cert.is_root ? 'ROOT' : `CA ${cert.index}`}</div>
                      <div className="cert-details">
                        <div><strong>Subject:</strong> {cert.subject}</div>
                        <div><strong>Issuer:</strong> {cert.issuer}</div>
                        <div className="cert-validity">
                          Valid: {new Date(cert.not_before).toLocaleDateString()} - {new Date(cert.not_after).toLocaleDateString()}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="card-actions">
              <button
                className="btn btn-primary"
                disabled={!allFilesUploaded}
                onClick={() => setCurrentStep('configure')}
              >
                Continue to Configuration
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
                  <polyline points="9 18 15 12 9 6"/>
                </svg>
              </button>
            </div>
          </div>
        )}

        {/* Step 2: Configure */}
        {currentStep === 'configure' && (
          <div className="card fade-in">
            <div className="card-header">
              <h2>Configuration</h2>
              <p>Set the keystore parameters for your Kafka connection</p>
            </div>

            <div className="config-grid">
              <div className="form-group">
                <label htmlFor="bootstrap">Bootstrap Server</label>
                <input
                  type="text"
                  id="bootstrap"
                  value={bootstrap}
                  onChange={(e) => setBootstrap(e.target.value)}
                  placeholder="kafka.example.com:443"
                />
                <span className="form-hint">Kafka broker address with port</span>
              </div>

              <div className="form-group">
                <label htmlFor="alias">Alias Name</label>
                <input
                  type="text"
                  id="alias"
                  value={alias}
                  onChange={(e) => setAlias(e.target.value)}
                  placeholder="kafka-client"
                />
                <span className="form-hint">Identifier for the certificate entry</span>
              </div>

              <div className="form-group">
                <label htmlFor="password">Store Password</label>
                <input
                  type="password"
                  id="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="changeit"
                />
                <span className="form-hint">Password for keystore and truststore</span>
              </div>
            </div>

            <div className="card-actions">
              <button className="btn btn-secondary" onClick={() => setCurrentStep('upload')}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
                  <polyline points="15 18 9 12 15 6"/>
                </svg>
                Back
              </button>
              <button className="btn btn-primary" onClick={() => setCurrentStep('generate')}>
                Continue to Generate
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
                  <polyline points="9 18 15 12 9 6"/>
                </svg>
              </button>
            </div>
          </div>
        )}

        {/* Step 3: Generate */}
        {currentStep === 'generate' && (
          <div className="card fade-in">
            <div className="card-header">
              <h2>Generate Keystores</h2>
              <p>Review your configuration and generate the files</p>
            </div>

            <div className="summary-card">
              <h3>Summary</h3>
              <div className="summary-grid">
                <div className="summary-item">
                  <span className="summary-label">Bootstrap Server</span>
                  <span className="summary-value">{bootstrap || 'Not specified'}</span>
                </div>
                <div className="summary-item">
                  <span className="summary-label">Alias</span>
                  <span className="summary-value">{alias}</span>
                </div>
                <div className="summary-item">
                  <span className="summary-label">Files Uploaded</span>
                  <span className="summary-value">4 certificates</span>
                </div>
              </div>
            </div>

            <div className="output-preview">
              <h3>Output Files</h3>
              <div className="file-list">
                <div className="file-item">
                  <div className="file-icon jks">JKS</div>
                  <div className="file-info">
                    <strong>truststore.jks</strong>
                    <span>Java KeyStore containing CA certificates</span>
                  </div>
                </div>
                <div className="file-item">
                  <div className="file-icon p12">P12</div>
                  <div className="file-info">
                    <strong>keystore.p12</strong>
                    <span>PKCS12 keystore with client certificate and key</span>
                  </div>
                </div>
                <div className="file-item">
                  <div className="file-icon props">CFG</div>
                  <div className="file-info">
                    <strong>client-ssl.properties</strong>
                    <span>Kafka SSL configuration file</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="card-actions">
              <button className="btn btn-secondary" onClick={() => setCurrentStep('configure')}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
                  <polyline points="15 18 9 12 15 6"/>
                </svg>
                Back
              </button>
              <button
                className="btn btn-primary btn-generate"
                onClick={handleGenerate}
                disabled={isLoading}
              >
                {isLoading ? (
                  <>
                    <span className="spinner"></span>
                    Generating...
                  </>
                ) : (
                  <>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
                      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                      <polyline points="7 10 12 15 17 10"/>
                      <line x1="12" y1="15" x2="12" y2="3"/>
                    </svg>
                    Generate & Download
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {/* Step 4: Test */}
        {currentStep === 'test' && (
          <div className="card fade-in">
            <div className="card-header">
              <h2>Test Kafka Connection</h2>
              <p>Upload the generated files to test connectivity</p>
            </div>

            <div className="test-upload-grid">
              <div className={`upload-card ${testFiles.truststore ? 'has-file' : ''}`}>
                <input
                  type="file"
                  accept=".jks"
                  onChange={(e) => handleTestFileChange('truststore', e.target.files?.[0] || null)}
                  id="file-truststore"
                />
                <label htmlFor="file-truststore">
                  <div className="upload-icon">
                    {testFiles.truststore ? (
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="20 6 9 17 4 12"/>
                      </svg>
                    ) : (
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                        <polyline points="17 8 12 3 7 8"/>
                        <line x1="12" y1="3" x2="12" y2="15"/>
                      </svg>
                    )}
                  </div>
                  <div className="upload-text">
                    <strong>Truststore</strong>
                    <span>{testFiles.truststore?.name || 'truststore.jks'}</span>
                  </div>
                </label>
              </div>

              <div className={`upload-card ${testFiles.keystore ? 'has-file' : ''}`}>
                <input
                  type="file"
                  accept=".p12,.jks"
                  onChange={(e) => handleTestFileChange('keystore', e.target.files?.[0] || null)}
                  id="file-keystore"
                />
                <label htmlFor="file-keystore">
                  <div className="upload-icon">
                    {testFiles.keystore ? (
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="20 6 9 17 4 12"/>
                      </svg>
                    ) : (
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                        <polyline points="17 8 12 3 7 8"/>
                        <line x1="12" y1="3" x2="12" y2="15"/>
                      </svg>
                    )}
                  </div>
                  <div className="upload-text">
                    <strong>Keystore</strong>
                    <span>{testFiles.keystore?.name || 'keystore.p12'}</span>
                  </div>
                </label>
              </div>
            </div>

            <div className="config-grid">
              <div className="form-group">
                <label htmlFor="test-bootstrap">Bootstrap Server</label>
                <input
                  type="text"
                  id="test-bootstrap"
                  value={testBootstrap}
                  onChange={(e) => setTestBootstrap(e.target.value)}
                  placeholder="kafka.example.com:443"
                />
              </div>

              <div className="form-group">
                <label htmlFor="test-password">Store Password</label>
                <input
                  type="password"
                  id="test-password"
                  value={testPassword}
                  onChange={(e) => setTestPassword(e.target.value)}
                  placeholder="changeit"
                />
              </div>
            </div>

            {testResult && (
              <div className={`test-result ${testResult.success ? 'success' : 'error'}`}>
                <div className="test-result-header">
                  {testResult.success ? (
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="24" height="24">
                      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                      <polyline points="22 4 12 14.01 9 11.01"/>
                    </svg>
                  ) : (
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="24" height="24">
                      <circle cx="12" cy="12" r="10"/>
                      <line x1="15" y1="9" x2="9" y2="15"/>
                      <line x1="9" y1="9" x2="15" y2="15"/>
                    </svg>
                  )}
                  <span>{testResult.message}</span>
                </div>
                {testResult.topics && testResult.topics.length > 0 && (
                  <div className="topics-list">
                    <strong>Topics found ({testResult.topics.length}):</strong>
                    <ul>
                      {testResult.topics.slice(0, 10).map((topic, i) => (
                        <li key={i}>{topic}</li>
                      ))}
                      {testResult.topics.length > 10 && (
                        <li className="more">...and {testResult.topics.length - 10} more</li>
                      )}
                    </ul>
                  </div>
                )}
              </div>
            )}

            <div className="card-actions">
              <button className="btn btn-secondary" onClick={() => setCurrentStep('generate')}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
                  <polyline points="15 18 9 12 15 6"/>
                </svg>
                Back
              </button>
              <button
                className="btn btn-primary"
                onClick={handleTestConnection}
                disabled={isLoading || !testFiles.truststore || !testFiles.keystore || !testBootstrap}
              >
                {isLoading ? (
                  <>
                    <span className="spinner"></span>
                    Testing...
                  </>
                ) : (
                  <>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
                      <polygon points="5 3 19 12 5 21 5 3"/>
                    </svg>
                    Test Connection
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {/* Command Reference */}
        <div className="card commands-card">
          <div className="card-header">
            <h2>Manual Commands Reference</h2>
            <p>Use these commands to test your Kafka connection manually</p>
          </div>

          <div className="commands-grid">
            <div className="command-block">
              <h4>List Topics</h4>
              <pre><code>{`./kafka-topics.sh --list \\
  --command-config client-ssl.properties \\
  --bootstrap-server ${bootstrap || '<bootstrap>'}:443`}</code></pre>
            </div>

            <div className="command-block">
              <h4>Consume Messages</h4>
              <pre><code>{`./kafka-console-consumer.sh \\
  --topic <topic-name> \\
  --from-beginning --max-messages 1 \\
  --consumer.config client-ssl.properties \\
  --bootstrap-server ${bootstrap || '<bootstrap>'}:443`}</code></pre>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="footer">
        <p>mTLS Configurator - Secure Kafka SSL/TLS Setup</p>
      </footer>
    </div>
  );
}

export default App;
