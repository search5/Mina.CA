import datetime
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# 개인키 생성
def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

# 개인키 PEM 포맷 및 암호화
def serialize_private_key(private_key, password: str) -> str:
    encryption_algorithm = serialization.BestAvailableEncryption(password.encode('utf-8')) if password else serialization.NoEncryption()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )
    return pem.decode('utf-8')

# 암호화된 개인키 로드
def load_private_key(pem_data: str, password: str):
    return serialization.load_pem_private_key(
        pem_data.encode('utf-8'),
        password=password.encode('utf-8') if password else None
    )

# DN 구성 헬퍼
def create_name(subject_dict):
    name_attributes = []
    oid_map = {
        'country': NameOID.COUNTRY_NAME,
        'province': NameOID.STATE_OR_PROVINCE_NAME,
        'locality': NameOID.LOCALITY_NAME,
        'organization': NameOID.ORGANIZATION_NAME,
        'organizational_unit': NameOID.ORGANIZATIONAL_UNIT_NAME,
        'common_name': NameOID.COMMON_NAME,
        'email_address': NameOID.EMAIL_ADDRESS,
    }
    for key, value in subject_dict.items():
        if value and key in oid_map:
            name_attributes.append(x509.NameAttribute(oid_map[key], value))
    return x509.Name(name_attributes)

# Root CA 생성 (Self-signed)
def create_root_ca(subject_dict, password: str, valid_days: int):
    private_key = generate_private_key()
    subject = create_name(subject_dict)
    issuer = subject # Root CA는 self-signed
    
    now = datetime.datetime.utcnow()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(days=valid_days))
    
    # Root CA 기본 제약 조건 및 Key Usage 설정
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=1),
        critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256()
    )
    
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    key_pem = serialize_private_key(private_key, password)
    
    return cert_pem, key_pem

# Intermediate CA 생성
def create_intermediate_ca(subject_dict, password: str, valid_days: int, parent_cert_pem: str, parent_key_pem: str, parent_password: str):
    private_key = generate_private_key()
    subject = create_name(subject_dict)
    
    parent_cert = x509.load_pem_x509_certificate(parent_cert_pem.encode('utf-8'))
    parent_key = load_private_key(parent_key_pem, parent_password)
    
    now = datetime.datetime.utcnow()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(parent_cert.subject)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(days=valid_days))
    
    # Intermediate CA 기본 제약 조건 (pathlen:0) 및 Key Usage 설정
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    
    certificate = builder.sign(
        private_key=parent_key,
        algorithm=hashes.SHA256()
    )
    
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    key_pem = serialize_private_key(private_key, password)
    
    return cert_pem, key_pem

# 클라이언트(Leaf) 인증서 생성 (Intermediate CA 서명)
def create_client_certificate(subject_dict, sans, valid_days: int, ca_cert_pem: str, ca_key_pem: str, ca_password: str, client_public_key_pem: str):
    # 크롬 브라우저 규격 제한: 최종 인증서 유효기간 최대 398일 제한 적용
    if valid_days > 398:
        valid_days = 398
        
    subject = create_name(subject_dict)
    
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode('utf-8'))
    ca_key = load_private_key(ca_key_pem, ca_password)
    
    # 클라이언트 공개키 로드
    client_public_key = serialization.load_pem_public_key(client_public_key_pem.encode('utf-8'))
    
    now = datetime.datetime.utcnow()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(client_public_key)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(days=valid_days))
    
    # 클라이언트 기본 제약 조건 (CA:FALSE)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )
    # Key Usage (digitalSignature, keyEncipherment)
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    # Extended Key Usage (serverAuth, clientAuth)
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
        ]),
        critical=True
    )
    
    # SAN (Subject Alternative Name) 필수 설정
    if sans:
        san_list = []
        for san in sans:
            # IP 주소 판별
            try:
                ip = ipaddress.ip_address(san)
                san_list.append(x509.IPAddress(ip))
            except ValueError:
                san_list.append(x509.DNSName(san))
        
        # 만약 Common Name도 SAN에 포함되어 있지 않다면 추가해주어 크롬 호환성 보장
        cn = subject_dict.get('common_name')
        if cn:
            try:
                ip = ipaddress.ip_address(cn)
                if x509.IPAddress(ip) not in san_list:
                    san_list.append(x509.IPAddress(ip))
            except ValueError:
                if x509.DNSName(cn) not in san_list:
                    san_list.append(x509.DNSName(cn))

        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )
        
    certificate = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256()
    )
    
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    return cert_pem

# CSR 파일 로드 및 파싱 메타데이터 반환
def load_csr_metadata(csr_pem_data: str):
    csr = x509.load_pem_x509_csr(csr_pem_data.encode('utf-8'))
    subject_dict = {}
    
    # Subject 정보 추출
    for attribute in csr.subject:
        oid = attribute.oid
        val = attribute.value
        if oid == NameOID.COUNTRY_NAME:
            subject_dict['country'] = val
        elif oid == NameOID.STATE_OR_PROVINCE_NAME:
            subject_dict['province'] = val
        elif oid == NameOID.LOCALITY_NAME:
            subject_dict['locality'] = val
        elif oid == NameOID.ORGANIZATION_NAME:
            subject_dict['organization'] = val
        elif oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
            subject_dict['organizational_unit'] = val
        elif oid == NameOID.COMMON_NAME:
            subject_dict['common_name'] = val
        elif oid == NameOID.EMAIL_ADDRESS:
            subject_dict['email_address'] = val
            
    # SAN (Subject Alternative Name) 추출
    sans = []
    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                sans.append(name.value)
            elif isinstance(name, x509.IPAddress):
                sans.append(str(name.value))
    except x509.ExtensionNotFound:
        pass
        
    # 공개키 PEM 추출
    public_key_pem = csr.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return subject_dict, sans, public_key_pem

