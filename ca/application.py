import os
import shlex
import shutil
import subprocess
import logging
import tempfile
import time
from datetime import timedelta, datetime
from io import BytesIO, StringIO
from pathlib import Path
from tempfile import NamedTemporaryFile
from zipfile import ZipFile, ZIP_DEFLATED

import paginate as paginate
import pexpect
from flask import Flask, render_template, request, jsonify, url_for, redirect, flash, send_file
from paginate_sqlalchemy import SqlalchemyOrmWrapper
from slugify import slugify
from sqlalchemy import desc, Column
from sqlalchemy.orm.attributes import flag_modified
from werkzeug.datastructures import MultiDict

from ca.cnf import OpenSSLCnf
from ca.database import db_session
from ca.forms.CAForm import CAForm
from ca.forms.CertificateForm import CertificateForm
from ca.lib import paginate_link_tag
from ca.models import CA, Certficate

app = Flask(__name__)
os.environ["CA_ROOTS"] = "/opt/ca"


@app.route('/')
def mina_ca_main():
    return redirect(url_for('login_page'))


@app.route('/login')
def login_page():
    return render_template('login.jinja2')


@app.route("/ca")
def ca_list():
    current_page = request.args.get("page", 1, type=int)
    search_option = request.args.get("search_option", '')
    search_word = request.args.get("search_word", '')

    search_column: Column = None
    if search_option:
        search_column: Column = getattr(CA, search_option)

    page_url = url_for("ca_list")
    if search_word:
        page_url = url_for("ca_list", search_option=search_option, search_word=search_word)
        page_url = str(page_url) + "&page=$page"
    else:
        page_url = str(page_url) + "?page=$page"

    items_per_page = 10

    records = db_session.query(CA)
    if search_word:
        records = records.filter(search_column.ilike('%{}%'.format(search_word)))
    records = records.order_by(desc(CA.id))
    total_cnt = records.count()

    paginator = paginate.Page(records, current_page, page_url=page_url,
                              items_per_page=items_per_page,
                              wrapper_class=SqlalchemyOrmWrapper)

    return render_template("ca_list.html", paginator=paginator,
                           paginate_link_tag=paginate_link_tag,
                           page_url=page_url, items_per_page=items_per_page,
                           total_cnt=total_cnt, page=current_page)


@app.route("/ca/add")
def ca_add():
    form = CAForm()

    # Country Name: 2자리 국가코드를 입력한다.
    # State or Province Name: 인증기관이 위치한 주 또는 지역 이름을 입력한다.
    # Locality Name: 인증기관이 위치한 도시 이름을 입력한다.
    # Organization Name: 인증기관의 이름을 입력한다.
    # Organizational Unit Name: 인증서를 발급하는 인증기관의 부서명을 입력한다.
    # Common Name: 인증기관의 도메인 이름을 입력한다. 실제 존재하지 않아도 된다.
    # Email Address: 입력하지 않는다.

    return render_template("ca_add.html", form=form)


@app.route("/ca/add", methods=["POST"])
def ca_add_post():
    ret = {"success": True}

    ca_record = CA()

    # WTForms는 초깃값의 인스턴스는 MultiDict를 받았을때만 정상 출력한다.
    req_json = request.get_json()

    # 인증기관명(한글)과 인증 디렉터리가 같은 경우 생성하면 안된다.
    is_ca_record = CA.query.filter(CA.catitle == req_json.get('catitle'),
                                   CA.catop == req_json.get('catop')).first()
    if is_ca_record:
        return jsonify(success=False, message='이미 등록된 CA가 있습니다. 진행할 수 없습니다')

    form = CAForm(MultiDict(req_json))

    if form.validate():
        form.populate_obj(ca_record)

        # 여기에서 openssl.cnf 파일을 복사해서 DB에 박아넣음
        # 윈도우는 존재하지 않을 수 있으나 추후 처리하겠음(TODO)
        with Path("/usr/lib/ssl/openssl.cnf") as p:
            if p.exists():
                # 인증기관 저장 디렉터리명 변경(임시로 환경설정에서 읽도록 변경)
                # 인증기관 디렉터리는 UUID로 관리하도록 함(코드 생성보다 이게 나을듯)
                new_ca_root = Path(os.environ["CA_ROOTS"]) / ca_record.catop
                new_ca_root.mkdir(parents=True, exist_ok=True)

                # create the directory hierarchy
                for item in ("certs", "crl", "newcerts", "private"):
                    Path(new_ca_root / item).mkdir(parents=True, exist_ok=True)

                Path(new_ca_root / "index.txt").write_text('')
                Path(new_ca_root / "crlnumber").write_text('01\n')

                ca_root_resolve = str(new_ca_root.resolve())

                cnf_editor = OpenSSLCnf(ca_record.catop)
                cnf_editor.load("[DEFAULT]\n{}".format(p.read_text("utf-8")))
                cnf_editor.default_ca = 'CA_default'
                cnf_editor.add_ca_info('dir', ca_root_resolve)
                ca_record.caconfig = cnf_editor.export()

                logging.debug("Making CA certificate ...\n")

                # cakey.pem은 여기서 먼저 생성한다.
                CAKEY = (new_ca_root / "private" / "cakey.pem").resolve()

                PASSWD_FILE = tempfile.NamedTemporaryFile()
                PASSWD_FILE.write(ca_record.capass.encode("utf-8"))
                PASSWD_FILE.seek(0)
                CAKEY_GEN = f"openssl genrsa -aes256 -passout file:{PASSWD_FILE.name} -out {CAKEY} 4096"

                ret_cakey_gen = subprocess.check_output(shlex.split(CAKEY_GEN))

                # cnf 편집해서 기본적으로 사용할 속성들을 모두 넣어놓기
                cnf_editor.add_req_attribute('countryName', ca_record.country_name)
                cnf_editor.add_req_attribute('stateOrProvinceName', ca_record.province_name)
                cnf_editor.add_req_attribute('localityName', ca_record.locality_name)
                cnf_editor.add_req_attribute('0.organizationName', ca_record.organization_name)
                cnf_editor.add_req_attribute('organizationalUnitName', ca_record.organizational_unit_name)
                cnf_editor.add_req_attribute('commonName', ca_record.common_name)
                cnf_editor.add_req_attribute('emailAddress', ca_record.email_address)

                ssl_cnf = NamedTemporaryFile("w+")
                ssl_cnf.write(cnf_editor.export())
                ssl_cnf.seek(0)

                REQ = f"openssl req -config {ssl_cnf.name} -passin file:{PASSWD_FILE.name}"

                CAREQ = (new_ca_root / "careq.pem").resolve()
                CACERT = (new_ca_root / "cacert.pem").resolve()

                # TODO: extra options... (1 args)
                RET1 = f"{REQ} -new -key {CAKEY} -out {CAREQ} -sha256"

                # ssl_req = pexpect.spawn(RET1, encoding='utf-8')
                # ssl_req.expect('Enter PEM pass phrase:')
                # ssl_req.sendline(ca_record.capass)
                # ssl_req.expect('Verifying - Enter PEM pass phrase:')
                # ssl_req.sendline(ca_record.capass)
                #
                # ssl_req.expect('Country Name.*:')
                # ssl_req.sendline(ca_record.country_name)
                # ssl_req.expect('State or Province Name.*:')
                # ssl_req.sendline(ca_record.province_name)
                # ssl_req.expect('Locality Name.*:')
                # ssl_req.sendline(ca_record.locality_name)
                # ssl_req.expect('Organization Name.*:')
                # ssl_req.sendline(ca_record.organization_name)
                # ssl_req.expect('Organizational Unit Name.*:')
                # ssl_req.sendline(ca_record.organizational_unit_name)
                # ssl_req.expect('Common Name.*:')
                # ssl_req.sendline(ca_record.common_name)
                # ssl_req.expect('Email Address.*:')
                # ssl_req.sendline(ca_record.email_address)
                # ssl_req.expect('A challenge password.*:')
                # ssl_req.sendline(".")
                # ssl_req.expect('An optional company name.*:')
                # ssl_req.sendline(".")
                # ssl_req.expect(pexpect.EOF)
                # ssl_req.wait()
                ret = subprocess.check_output(shlex.split(RET1))
                # logging.debug(ret.returncode)

                CA_CMD = f"openssl ca -config {ssl_cnf.name}"

                RET2 = (f"{CA_CMD} -create_serial"
                        " -out {CACERT} -days {ca_record.cadays} -batch"
                        " -keyfile {CAKEY} -selfsign"
                        " -extensions v3_ca"
                        " -infiles {CAREQ} -passin file:{PASSWD_FILE.name}")

                # ssl_ca = pexpect.spawn(RET2, encoding='utf-8')
                # ssl_ca.expect('Enter pass phrase for.*:')
                # ssl_ca.sendline(ca_record.capass)
                # ssl_ca.expect(pexpect.EOF)
                # ssl_ca.wait()
                ret = subprocess.check_output(shlex.split(RET2))
                # logging.debug(ret.returncode)

                logging.debug("CA certificate is in {CACERT}".format(CACERT=str(CACERT)))

        db_session.add(ca_record)
    else:
        ret["success"] = False

    return jsonify(ret)


@app.route("/ca/<catop>")
def ca_view(catop):
    current_page = request.args.get("page", 1, type=int)
    filter_type = request.args.get('filter_type', 'CERTIFICATED')
    logging.debug(filter_type)
    search_option = request.args.get("search_option", '')
    search_word = request.args.get("search_word", '')

    ca_record = CA.query.filter(CA.catop == catop).first()

    if not ca_record:
        flash('이러기야? 잘못된 CA를 조회하셨습니다')

    left_ca_days = (ca_record.created_date + timedelta(days=int(ca_record.cadays))) - datetime.now()
    left_ca_days = "{days} 일 {times}".format(days=left_ca_days.days,
                                             times=time.strftime("%H시 %M분 %S초", time.gmtime(left_ca_days.seconds)))

    search_column: Column = None
    if search_option:
        search_column: Column = getattr(Certficate, search_option)

    page_url = url_for("ca_view", catop=ca_record.catop, filter_type=filter_type)
    if search_word:
        page_url = url_for("ca_view", catop=ca_record.catop, search_option=search_option, search_word=search_word)
        page_url = str(page_url) + "&page=$page"
    else:
        page_url = str(page_url) + "?page=$page"

    items_per_page = 10

    records = db_session.query(Certficate).filter(Certficate.cert_status == filter_type)
    if search_word:
        records = records.filter(search_column.ilike('%{}%'.format(search_word)))
    records = records.order_by(desc(Certficate.id))
    total_cnt = records.count()

    paginator = paginate.Page(records, current_page, page_url=page_url,
                              items_per_page=items_per_page,
                              wrapper_class=SqlalchemyOrmWrapper)

    return render_template("ca_view.html", paginator=paginator,
                           paginate_link_tag=paginate_link_tag,
                           page_url=page_url, items_per_page=items_per_page,
                           total_cnt=total_cnt, page=current_page,
                           ca_record=ca_record, left_ca_days=left_ca_days)


@app.route("/ca/<catop>/csr/new")
def ca_csr_new(catop):
    ca_record = CA.query.filter(CA.catop == catop).first()

    if not ca_record:
        flash('이러기야? 잘못된 CA를 조회하셨습니다')

    left_ca_days = (ca_record.created_date + timedelta(days=int(ca_record.cadays))) - datetime.now()
    left_ca_days = "{days} 일 {times}".format(days=left_ca_days.days,
                                             times=time.strftime("%H시 %M분 %S초", time.gmtime(left_ca_days.seconds)))

    form = CertificateForm()

    return render_template('ca_csr_new.html', ca_record=ca_record, left_ca_days=left_ca_days, form=form)


@app.route("/ca/<catop>/csr/new", methods=["POST"])
def cert_csr_new_post(catop):
    ca_record = CA.query.filter(CA.catop == catop).first()

    if not ca_record:
        flash('이러기야? 잘못된 CA를 조회하셨습니다')

    ret = {"success": True}

    cert_record = Certficate()

    # WTForms는 초깃값의 인스턴스는 MultiDict를 받았을때만 정상 출력한다.
    req_json = request.get_json()

    form = CertificateForm(MultiDict(req_json))

    if form.validate():
        form.populate_obj(cert_record)

        cert_record.cert_status = "CSR"

        ssl_cnf = NamedTemporaryFile("w+")
        ssl_cnf.write(ca_record.caconfig)
        ssl_cnf.seek(0)

        REQ = "openssl req -config {ssl_cnf}".format(ssl_cnf=ssl_cnf.name)

        new_ca_root = Path(os.environ["CA_ROOTS"]) / ca_record.catop

        certs_dir = new_ca_root / "certs" / cert_record.cert_link
        certs_dir.mkdir(parents=True, exist_ok=True)

        NEWKEY = (certs_dir / "key.pem").resolve()
        NEWREQ = (certs_dir / "csr.pem").resolve()

        # TODO: extra options... (1 args)
        RET = "{REQ} -new -keyout {NEWKEY} -out {NEWREQ} -days {CERT_DAYS}".format(
            REQ=REQ, NEWKEY=str(NEWKEY), NEWREQ=str(NEWREQ), CERT_DAYS=cert_record.cert_days)

        ssl_req = pexpect.spawn(RET, encoding='utf-8')
        ssl_req.expect('Enter PEM pass phrase:')
        ssl_req.sendline(cert_record.cert_pass)
        ssl_req.expect('Verifying - Enter PEM pass phrase:')
        ssl_req.sendline(cert_record.cert_pass)

        ssl_req.expect('Country Name.*:')
        ssl_req.sendline(cert_record.country_name)
        ssl_req.expect('State or Province Name.*:')
        ssl_req.sendline(cert_record.province_name)
        ssl_req.expect('Locality Name.*:')
        ssl_req.sendline(cert_record.locality_name)
        ssl_req.expect('Organization Name.*:')
        ssl_req.sendline(cert_record.organization_name)
        ssl_req.expect('Organizational Unit Name.*:')
        ssl_req.sendline(cert_record.organizational_unit_name)
        ssl_req.expect('Common Name.*:')
        ssl_req.sendline(cert_record.common_name)
        ssl_req.expect('Email Address.*:')
        ssl_req.sendline(cert_record.email_address)
        ssl_req.expect('A challenge password.*:')
        ssl_req.sendline(".")
        ssl_req.expect('An optional company name.*:')
        ssl_req.sendline(".")
        ssl_req.expect(pexpect.EOF)
        ssl_req.wait()

        logging.debug("Request is in {NEWREQ}, private key is in {NEWKEY}".format(NEWKEY=str(NEWKEY), NEWREQ=str(NEWREQ)))

        # 히스토리 남기기
        cert_record.parent_id = ca_record.id
        cert_record.history = [{
            "DATE": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "NOTE": "CSR 생성됨"
        }]

        db_session.add(cert_record)
    else:
        ret["success"] = False

    return jsonify(ret)


@app.route("/ca/<catop>/certificate/<cert_id>")
def certificate_view(catop, cert_id):
    ca_record = CA.query.filter(CA.catop == catop).first()

    if not ca_record:
        flash('이러기야? 잘못된 CA를 조회하셨습니다')

    left_ca_days = (ca_record.created_date + timedelta(days=int(ca_record.cadays))) - datetime.now()

    left_ca_days = "{days} 일 {times}".format(days=left_ca_days.days,
                                             times=time.strftime("%H시 %M분 %S초", time.gmtime(left_ca_days.seconds)))

    cert_record = Certficate.query.filter(Certficate.id == cert_id).first()

    return render_template("certificate_view.html", ca_record=ca_record, left_ca_days=left_ca_days, cert_record=cert_record)


@app.route("/ca/<catop>/certificate/<cert_id>", methods=["DELETE"])
def certificate_delete(catop, cert_id):
    ca_record = CA.query.filter(CA.catop == catop).first()

    if not ca_record:
        flash('이러기야? 잘못된 CA를 조회하셨습니다')

    ret = {"success": True, 'message': ''}

    cert_record = Certficate.query.filter(Certficate.id == cert_id).first()
    if cert_record and cert_record.cert_status == "CSR":
        db_session.delete(cert_record)

        # 인증서 디렉터리 삭제
        new_ca_root = Path(os.environ["CA_ROOTS"]) / ca_record.catop

        certs_dir = new_ca_root / "certs" / cert_record.cert_link
        shutil.rmtree(certs_dir)

        ret['message'] = '삭제되었습니다'
    else:
        ret['message'] = '인증서는 CSR 단계에서만 삭제할 수 있습니다'

    return jsonify(ret)


@app.route("/ca/<catop>/certificate/<cert_id>", methods=["POST"])
def certificate_sign(catop, cert_id):
    ca_record = CA.query.filter(CA.catop == catop).first()

    if not ca_record:
        flash('이러기야? 잘못된 CA를 조회하셨습니다')

    ret = {"success": True, 'message': ''}

    cert_record = Certficate.query.filter(Certficate.id == cert_id).first()
    if cert_record and cert_record.cert_status == "CSR":

        # SSL Config 동적 생성하기
        ssl_cnf = NamedTemporaryFile("w+")
        ssl_cnf.write(ca_record.caconfig)
        ssl_cnf.seek(0)

        CA_CMD = "openssl ca -config {ssl_cnf}".format(ssl_cnf=ssl_cnf.name)

        new_ca_root = Path(os.environ["CA_ROOTS"]) / ca_record.catop
        certs_dir = new_ca_root / "certs" / cert_record.cert_link

        NEWREQ = (certs_dir / "csr.pem").resolve()
        NEWCERT = (certs_dir / "cert.pem").resolve()

        # TODO: extra options... (1 args)
        RET = "{CA_CMD} -policy policy_anything -out {NEWCERT} -infiles {NEWREQ}".format(
            CA_CMD=CA_CMD, NEWCERT=str(NEWCERT), NEWREQ=str(NEWREQ))

        ssl_sign = pexpect.spawn(RET, encoding='utf-8')
        ssl_sign.expect('Enter pass phrase for.*:')
        ssl_sign.sendline(ca_record.capass)
        ssl_sign.expect('Sign the certificate.*')
        ssl_sign.sendline('Y')
        ssl_sign.expect('[0-9]+ out of [0-9]+ certificate requests certified, commit.*')
        ssl_sign.sendline('Y')
        ssl_sign.expect(pexpect.EOF)
        ssl_sign.wait()

        certificate_date = datetime.now()
        cert_record.cert_status = 'CERTIFICATED'
        cert_record.certificate_date = certificate_date
        cert_record.history.append({
            "DATE": certificate_date.strftime("%Y-%m-%d %H:%M:%S"), "NOTE": "인증기관 \"{CATITLE} \"이 인증서 사인함".format(CATITLE=ca_record.catitle)
        })
        flag_modified(cert_record, "history")

        logging.debug("Signed certificate is in {NEWCERT}".format(NEWCERT=str(NEWCERT)))

        ret['message'] = '이 인증서를 사인했습니다'
    else:
        ret['message'] = '인증서는 CSR 단계에서만 사인할 수 있습니다'

    return jsonify(ret)


@app.route("/ca/<catop>/certificate/<cert_id>/revoke", methods=["POST"])
def certificate_revoke(catop, cert_id):
    ca_record = CA.query.filter(CA.catop == catop).first()

    if not ca_record:
        flash('이러기야? 잘못된 CA를 조회하셨습니다')

    ret = {"success": True, 'message': ''}

    cert_record = Certficate.query.filter(Certficate.id == cert_id).first()
    if cert_record and cert_record.cert_status == "CERTIFICATED":

        # SSL Config 동적 생성하기
        ssl_cnf = NamedTemporaryFile("w+")
        ssl_cnf.write(ca_record.caconfig)
        ssl_cnf.seek(0)

        CA_CMD = "openssl ca -config {ssl_cnf}".format(ssl_cnf=ssl_cnf.name)

        # 인증서 승인 취소
        new_ca_root = Path(os.environ["CA_ROOTS"]) / ca_record.catop

        certs_dir = new_ca_root / "certs" / cert_record.cert_link

        NEWCERT = (certs_dir / "cert.pem").resolve()

        # 인증 취소 사유
        reason = request.get_json().get('reason')

        RET = "{CA_CMD} -revoke {NEWCERT} -crl_reason {REASON}".format(
            CA_CMD=CA_CMD, NEWCERT=str(NEWCERT), REASON=reason)

        ssl_revoke = pexpect.spawn(RET, encoding='utf-8')
        ssl_revoke.expect('Enter pass phrase for .*:')
        ssl_revoke.sendline(ca_record.capass)
        ssl_revoke.expect(pexpect.EOF)
        ssl_revoke.wait()

        certificate_date = datetime.now()
        cert_record.cert_status = 'REVOKE'
        cert_record.certificate_date = certificate_date
        cert_record.history.append({
            "DATE": certificate_date.strftime("%Y-%m-%d %H:%M:%S"),
            "NOTE": "인증기관 \"{CATITLE} \"에서 인증 취소함".format(CATITLE=ca_record.catitle)
        })
        flag_modified(cert_record, "history")

        ret['message'] = '취소되었습니다'
    else:
        ret['message'] = '인증서는 CERTIFICATED 단계에서만 취소할 수 있습니다'

    return jsonify(ret)


@app.route("/ca/<catop>/certificate/<cert_id>/download")
def certificate_download(catop, cert_id):
    ca_record = CA.query.filter(CA.catop == catop).first()

    if not ca_record:
        flash('이러기야? 잘못된 CA를 조회하셨습니다')

    cert_record = Certficate.query.filter(Certficate.id == cert_id).first()
    if cert_record and cert_record.cert_status == "CERTIFICATED":
        new_ca_root = Path(os.environ["CA_ROOTS"]) / ca_record.catop

        CACERT = new_ca_root / "cacert.pem"

        certs_dir = new_ca_root / "certs" / cert_record.cert_link

        NEWCERT = certs_dir / "cert.pem"
        NEWKEY = certs_dir / "key.pem"

        # cert 파일은 -----BEGIN CERTIFICATE----- 부터 마지막줄까지만 찾아서 보내줘야 함
        # 왜냐하면 시스템마다 구분자 이전은 인식하지 않을 수 있기 때문

        certificate_identifier = "-----BEGIN CERTIFICATE-----"

        ca_cert_io = NamedTemporaryFile('w+')
        certificate_content = CACERT.open('r').read()
        certificate_ident_start = certificate_content.find(certificate_identifier)
        ca_cert_io.write(certificate_content[certificate_ident_start:])
        ca_cert_io.seek(0)

        cert_io = NamedTemporaryFile('w+')
        certificate_content = NEWCERT.open('r').read()
        certificate_ident_start = certificate_content.find(certificate_identifier)
        cert_io.write(certificate_content[certificate_ident_start:])
        cert_io.seek(0)

        # temporary zip file create
        zip_file = BytesIO()
        cert_zip = ZipFile(zip_file, 'w', ZIP_DEFLATED, True)
        cert_zip.write(cert_io.name, "{}_cert.pem".format(cert_record.cert_link))
        cert_zip.write(str(NEWKEY.resolve()), "{}_key.pem".format(cert_record.cert_link))

        if request.args.get('ca_include') == 'true':
            cert_zip.write(ca_cert_io.name, "{}_cacert.pem".format(ca_record.catop))

        cert_zip.close()

        zip_file.seek(0)

        return send_file(zip_file, mimetype="application/zip", as_attachment=True, attachment_filename='{}_cert.zip'.format(cert_record.cert_link))

    return '잘못된 요청입니다'


@app.teardown_appcontext
def shutdown_session(exception=None):
    if exception:
        db_session.rollback()
    else:
        db_session.commit()

    db_session.remove()

@app.context_processor
def mina_processor():
    return dict(
        certificate_status=lambda x: 'active' if request.args.get('filter_type', 'CERTIFICATED') == x else 'link-dark'
    )