import os
from datetime import timedelta, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile

import paginate as paginate
import pexpect
from flask import Flask, render_template, request, jsonify, url_for, redirect, flash
from paginate_sqlalchemy import SqlalchemyOrmWrapper
from slugify import slugify
from sqlalchemy import desc, Column
from werkzeug.datastructures import MultiDict

from ca.database import db_session
from ca.forms.CAForm import CAForm
from ca.forms.CertificateForm import CertificateForm
from ca.lib import paginate_link_tag
from ca.models import CA, Certficate

app = Flask(__name__)


@app.route('/')
def mina_ca_main():
    return redirect(url_for('ca_list'))


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
                caconfig = p.read_text()
                caconfig = caconfig.replace("./demoCA", ca_root_resolve)
                ca_record.caconfig = caconfig

                print("Making CA certificate ...\n")

                ssl_cnf = NamedTemporaryFile("w+")
                ssl_cnf.write(caconfig)
                ssl_cnf.seek(0)

                REQ = "openssl req -config {ssl_cnf}".format(ssl_cnf=ssl_cnf.name)

                CAKEY = (new_ca_root / "private" / "cakey.pem").resolve()
                CAREQ = (new_ca_root / "careq.pem").resolve()
                CACERT = (new_ca_root / "cacert.pem").resolve()

                # TODO: extra options... (1 args)
                RET1 = "{REQ} -new -keyout {CAKEY} -out {CAREQ}".format(
                    REQ=str(REQ), CAKEY=str(CAKEY), CAREQ=str(CAREQ))

                ssl_req = pexpect.spawn(RET1, encoding='utf-8')
                ssl_req.expect('Enter PEM pass phrase:')
                ssl_req.sendline(ca_record.capass)
                ssl_req.expect('Verifying - Enter PEM pass phrase:')
                ssl_req.sendline(ca_record.capass)

                ssl_req.expect('Country Name.*:')
                ssl_req.sendline(ca_record.country_name)
                ssl_req.expect('State or Province Name.*:')
                ssl_req.sendline(ca_record.province_name)
                ssl_req.expect('Locality Name.*:')
                ssl_req.sendline(ca_record.locality_name)
                ssl_req.expect('Organization Name.*:')
                ssl_req.sendline(ca_record.organization_name)
                ssl_req.expect('Organizational Unit Name.*:')
                ssl_req.sendline(ca_record.organizational_unit_name)
                ssl_req.expect('Common Name.*:')
                ssl_req.sendline(ca_record.common_name)
                ssl_req.expect('Email Address.*:')
                ssl_req.sendline(ca_record.email_address)
                ssl_req.expect('A challenge password.*:')
                ssl_req.sendline(".")
                ssl_req.expect('An optional company name.*:')
                ssl_req.sendline(".")
                ssl_req.expect(pexpect.EOF)
                ssl_req.wait()

                CA_CMD = "openssl ca -config {ssl_cnf}".format(ssl_cnf=ssl_cnf.name)

                RET2 = ("{CA} -create_serial"
                        " -out {CACERT} -days {CADAYS} -batch"
                        " -keyfile {CAKEY} -selfsign"
                        " -extensions v3_ca"
                        " -infiles {CAREQ}").format(
                    CA=CA_CMD, CACERT=str(CACERT), CADAYS=str(ca_record.cadays), CAKEY=str(CAKEY), CAREQ=str(CAREQ))

                ssl_ca = pexpect.spawn(RET2, encoding='utf-8')
                ssl_ca.expect('Enter pass phrase for.*:')
                ssl_ca.sendline(ca_record.capass)
                ssl_ca.expect(pexpect.EOF)
                ssl_ca.wait()

                print("CA certificate is in {CACERT}".format(CACERT=str(CACERT)))

        db_session.add(ca_record)
        db_session.commit()
    else:
        ret["success"] = False

    return jsonify(ret)


@app.route("/ca/<catop>")
def ca_view(catop):
    ca_record = CA.query.filter(CA.catop == catop).first()

    if not ca_record:
        flash('이러기야? 잘못된 CA를 조회하셨습니다')

    left_ca_days = (ca_record.created_date + timedelta(days=int(ca_record.cadays))) - datetime.now()

    current_page = request.args.get("page", 1, type=int)
    search_option = request.args.get("search_option", '')
    search_word = request.args.get("search_word", '')

    search_column: Column = None
    if search_option:
        search_column: Column = getattr(Certficate, search_option)

    page_url = url_for("ca_view", catop=ca_record.catop)
    if search_word:
        page_url = url_for("ca_view", catop=ca_record.catop, search_option=search_option, search_word=search_word)
        page_url = str(page_url) + "&page=$page"
    else:
        page_url = str(page_url) + "?page=$page"

    items_per_page = 10

    records = db_session.query(Certficate)
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
                           ca_record=ca_record, left_ca_days=left_ca_days.days)


@app.route("/ca/<catop>/csr/new")
def ca_csr_new(catop):
    ca_record = CA.query.filter(CA.catop == catop).first()

    if not ca_record:
        flash('이러기야? 잘못된 CA를 조회하셨습니다')

    left_ca_days = (ca_record.created_date + timedelta(days=int(ca_record.cadays))) - datetime.now()

    form = CertificateForm()

    return render_template('ca_csr_new.html', ca_record=ca_record, left_ca_days=left_ca_days.days, form=form)


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

        certificate_name = slugify(cert_record.cert_title)

        certs_dir = new_ca_root / "certs" / certificate_name
        certs_dir.mkdir(parents=True, exist_ok=True)

        NEWKEY = (certs_dir / "key.pem").resolve()
        NEWREQ = (certs_dir / "csr.pem").resolve()

        # TODO: extra options... (1 args)
        RET = "{REQ} -new -keyout {NEWKEY} -out {NEWREQ} -days {CERT_DAYS}".format(
            REQ=REQ, NEWKEY=str(NEWKEY), NEWREQ=str(NEWREQ), CERT_DAYS=cert_record.cert_days)

        ssl_req = pexpect.spawn(RET, encoding='utf-8')
        ssl_req.expect('Enter PEM pass phrase:')
        ssl_req.sendline(ca_record.capass)
        ssl_req.expect('Verifying - Enter PEM pass phrase:')
        ssl_req.sendline(ca_record.capass)

        ssl_req.expect('Country Name.*:')
        ssl_req.sendline(ca_record.country_name)
        ssl_req.expect('State or Province Name.*:')
        ssl_req.sendline(ca_record.province_name)
        ssl_req.expect('Locality Name.*:')
        ssl_req.sendline(ca_record.locality_name)
        ssl_req.expect('Organization Name.*:')
        ssl_req.sendline(ca_record.organization_name)
        ssl_req.expect('Organizational Unit Name.*:')
        ssl_req.sendline(ca_record.organizational_unit_name)
        ssl_req.expect('Common Name.*:')
        ssl_req.sendline(ca_record.common_name)
        ssl_req.expect('Email Address.*:')
        ssl_req.sendline(ca_record.email_address)
        ssl_req.expect('A challenge password.*:')
        ssl_req.sendline(".")
        ssl_req.expect('An optional company name.*:')
        ssl_req.sendline(".")
        ssl_req.expect(pexpect.EOF)
        ssl_req.wait()

        print("Request is in {NEWREQ}, private key is in {NEWKEY}".format(NEWKEY=str(NEWKEY), NEWREQ=str(NEWREQ)))

        # 히스토리 남기기
        cert_record.parent_id = ca_record.id
        cert_record.history = [{
            "DATE": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "NOTE": "CSR 생성됨"
        }]

        db_session.add(cert_record)
        db_session.commit()
    else:
        ret["success"] = False

    return jsonify(ret)


@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()
