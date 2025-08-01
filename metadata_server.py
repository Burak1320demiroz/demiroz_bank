from http.server import HTTPServer, BaseHTTPRequestHandler
import json

# AWS Metadata simülasyonu
MOCK_METADATA = {
    'latest/meta-data/': {
        'ami-id': 'ami-12345678',
        'instance-id': 'i-1234567890abcdef0',
        'instance-type': 't2.micro',
        'local-hostname': 'ip-172-31-1-1',
        'local-ipv4': '172.31.1.1',
        'public-hostname': 'ec2-1-2-3-4.compute-1.amazonaws.com',
        'public-ipv4': '1.2.3.4',
        'security-groups': 'default',
        'iam/': 'security-credentials/'
    },
    'latest/meta-data/iam/security-credentials/': {
        'ec2-instance': 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nAWS_SESSION_TOKEN=AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA=='
    }
}

class MetadataHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Path'i temizle
        path = self.path.strip('/')
        
        # Metadata endpoint'lerini kontrol et
        if path in MOCK_METADATA:
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            
            # Dictionary ise JSON olarak döndür
            if isinstance(MOCK_METADATA[path], dict):
                self.wfile.write(json.dumps(MOCK_METADATA[path], indent=2).encode())
            else:
                self.wfile.write(MOCK_METADATA[path].encode())
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Not Found')

def run_server(port=80):
    server_address = ('', port)
    httpd = HTTPServer(server_address, MetadataHandler)
    print(f"Metadata server running on port {port}")
    httpd.serve_forever()

if __name__ == '__main__':
    run_server() 