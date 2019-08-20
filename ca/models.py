from sqlalchemy import Column, Integer, String, DateTime, Sequence, func, Text

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


# # create the directory hierarchy
#     mkdir ${CATOP}, $DIRMODE;
#     mkdir "${CATOP}/certs", $DIRMODE;
#     mkdir "${CATOP}/crl", $DIRMODE ;
#     mkdir "${CATOP}/newcerts", $DIRMODE;
#     mkdir "${CATOP}/private", $DIRMODE;
#     open OUT, ">${CATOP}/index.txt";
#     close OUT;
#     open OUT, ">${CATOP}/crlnumber";
#     print OUT "01\n";
#     close OUT;
#     # ask user for existing CA certificate
#     print "CA certificate filename (or enter to create)\n";
#     $FILE = "" unless defined($FILE = <STDIN>);
#     $FILE =~ s{\R$}{};
#     if ($FILE ne "") {
#         copy_pemfile($FILE,"${CATOP}/private/$CAKEY", "PRIVATE");
#         copy_pemfile($FILE,"${CATOP}/$CACERT", "CERTIFICATE");
#     } else {
#         print "Making CA certificate ...\n";
#         $RET = run("$REQ -new -keyout"
#                 . " ${CATOP}/private/$CAKEY"
#                 . " -out ${CATOP}/$CAREQ $EXTRA{req}");
#         $RET = run("$CA -create_serial"
#                 . " -out ${CATOP}/$CACERT $CADAYS -batch"
#                 . " -keyfile ${CATOP}/private/$CAKEY -selfsign"
#                 . " -extensions v3_ca $EXTRA{ca}"
#                 . " -infiles ${CATOP}/$CAREQ") if $RET == 0;
#         print "CA certificate is in ${CATOP}/$CACERT\n" if $RET == 0;
#     }

class CA(Base):
    __tablename__ = 'ca'

    idx = Column(Integer, Sequence('ca_seq'), primary_key=True)
    catitle = Column(String(255), comment='인증기관명')
    catop = Column(String(255), comment='CA 디렉터리')
    cakey = Column(String(255), comment='CA 비밀키 파일명')
    careq = Column(String(255), comment='CA 인증 요청서 파일명')
    cacert = Column(String(255), comment='CA 인증기관의 인증서')
    cadays = Column(String(255), comment='인증기관 유효기간(일단위)')
    caconfig = Column(Text, comment='CA 설정 파일 내용(인증기관별로 존재)')
    created_date = Column(DateTime, default=func.now(), comment='생성일자')
