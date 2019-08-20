import os
import uuid
from pathlib import Path

from flask import Flask, render_template, request, jsonify
from werkzeug.datastructures import MultiDict

from ca.database import db_session
from ca.forms.CAForm import CAForm
from ca.models import CA

app = Flask(__name__)


@app.route('/')
def mina_ca_main():
    return render_template('index.html')


@app.route("/ca")
def ca_list():
    # 여기서 CA 목록 받기
    return render_template("index.html")


@app.route("/ca/add")
def ca_add():
    form = CAForm()

    return render_template("ca_add.html", form=form)


@app.route("/ca/add", methods=["POST"])
def ca_add_post():
    ret = {"success": True}

    ca_record = CA()

    # WTForms는 초깃값의 인스턴스는 MultiDict를 받았을때만 정상 출력한다.
    form = CAForm(MultiDict(request.get_json()))

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

        db_session.add(ca_record)
        db_session.commit()
    else:
        ret["success"] = False

    return jsonify(ret)


@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()
