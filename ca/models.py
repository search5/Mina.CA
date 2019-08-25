from slugify import slugify
from sqlalchemy import Column, Integer, String, DateTime, Sequence, func, Text, \
    ForeignKey, JSON
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import relationship, backref

from ca.database import Base


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True)
    email = Column(String(120), unique=True)

    def __init__(self, name=None, email=None):
        self.name = name
        self.email = email

    def __repr__(self):
        return '<User %r>' % (self.name)


class CA(Base):
    __tablename__ = 'ca'

    id = Column(Integer, Sequence('ca_seq'), primary_key=True)
    parent_id = Column(Integer, ForeignKey('ca.id'))
    children = relationship("CA", backref=backref('parent', remote_side=[id]))
    catitle = Column(String(255), comment='인증기관명(한글)')
    capass = Column(String(255), comment='인증키 비밀번호')
    catop = Column(String(255), comment='CA 디렉터리')
    catype = Column(String(100), comment='CA 타입(Root, Intermediate)')
    country_name = Column(String(2), comment='국가코드')
    province_name = Column(String(255), comment='시/도')
    locality_name = Column(String(255), comment='시/군/구')
    organization_name = Column(String(255), comment='인증기관명')
    organizational_unit_name = Column(String(255), comment='인증기관 부서')
    common_name = Column(String(255), comment='CA 도메인')
    email_address = Column(String(255), comment='인증기관 담당자 이메일')
    cadays = Column(String(255), comment='인증기관 유효기간(일단위)')
    caconfig = Column(Text, comment='CA 설정 파일 내용(인증기관별로 존재)')
    created_date = Column(DateTime, default=func.now(), comment='생성일자')


class Certficate(Base):
    __tablename__ = 'certficate'

    id = Column(Integer, Sequence('certificate_seq'), primary_key=True)
    parent_id = Column(Integer, ForeignKey('ca.id'))
    cert_title = Column(String(255), comment='인증 서비스명(한글)')
    cert_pass = Column(String(255), comment='인증키 비밀번호')
    country_name = Column(String(2), comment='국가코드')
    province_name = Column(String(255), comment='시/도')
    locality_name = Column(String(255), comment='시/군/구')
    organization_name = Column(String(255), comment='인증서 기관')
    organizational_unit_name = Column(String(255), comment='인증서 부서')
    common_name = Column(String(255), comment='인증서 도메인(IP, Domain)')
    email_address = Column(String(255), comment='인증서 담당자 이메일')
    cert_days = Column(String(255), comment='인증서 유효기간(일단위)', doc='유효기간은 인증기관 유효일수보다 작아야 한다')
    cert_config = Column(Text, comment='CA 설정 파일 내용(인증서 별로 존재)', doc='왜냐하면 SN을 사용해야 하기 때문이다(추가 검증 필요)')
    cert_status = Column(String(100), comment='CSR, CERTIFICATED, REVOKE')
    history = Column(JSON, default=[], comment='인증서 이력')
    created_date = Column(DateTime, default=func.now(), comment='생성일자')
    certificate_date = Column(DateTime, comment='인증일자')

    @hybrid_property
    def cert_link(self):
        return slugify(self.cert_title)
