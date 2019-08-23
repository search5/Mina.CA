import os
import uuid
from pathlib import Path

import paginate as paginate
from flask import Flask, render_template, request, jsonify, url_for
from paginate_sqlalchemy import SqlalchemyOrmWrapper
from sqlalchemy import desc
from werkzeug.datastructures import MultiDict

from ca.database import db_session
from ca.forms.CAForm import CAForm
from ca.lib import paginate_link_tag
from ca.models import CA

app = Flask(__name__)


@app.route('/')
def mina_ca_main():
    return render_template('index.html')


@app.route("/ca")
def ca_list():
    current_page = request.args.get("page", 1, type=int)
    search_option = request.args.get("search_option", '')
    search_word = request.args.get("search_word", '')

    if search_option:
        search_column = getattr(CA, search_option)

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

    return render_template("index.html", paginator=paginator,
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

    # 기본값 세팅
    # if not req_json['cakey']: req_json['cakey'] = 'cakey.pem'
    # if req_json['careq']: req_json['careq'] = 'careq.pem'
    # if req_json['cacert']: req_json['cacert'] = 'cacert.pem'

    form = CAForm(MultiDict(req_json))

    if form.validate():
        form.populate_obj(ca_record)

        # 여기에서 openssl.cnf 파일을 복사해서 DB에 박아넣음
        # 윈도우는 존재하지 않을 수 있으나 추후 처리하겠음(TOOD)
        with Path("/usr/lib/ssl/openssl.cnf") as p:
            if p.exists():
                # 인증기관 저장 디렉터리명 변경(임시로 환경설정에서 읽도록 변경)
                # 인증기관 디렉터리는 UUID로 관리하도록 함(코드 생성보다 이게 나을듯)
                new_ca_root = Path(os.environ["CA_ROOTS"]) / ca_record.catop
                new_ca_root.mkdir(parents=True, exist_ok=True)

                caconfig = p.read_text()
                caconfig = caconfig.replace("./demoCA", str(new_ca_root.resolve()))
                ca_record.caconfig = caconfig

                # Enter PEM pass phrase: <password>⏎
                # Verifying - Enter PEM pass phrase: <password>

                # Country Name (2 letter code) [AU]:KR⏎
                # State or Province Name (full name) [Some-State]:⏎
                # Locality Name (eg, city) []:Seoul⏎
                # Organization Name (eg, company) [Internet Widgits Pty Ltd]:⏎
                # Organizational Unit Name (eg, section) []:⏎
                # Common Name (e.g. server FQDN or YOUR name) []:ca.insignal.co.kr⏎
                # Email Address []: ⏎
                #
                # Please enter the following 'extra' attributes
                # to be sent with your certificate request
                # A challenge password []:⏎
                # An optional company name []:⏎

        db_session.add(ca_record)
        db_session.commit()
    else:
        ret["success"] = False

    return jsonify(ret)


@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()
