import os
import logging
import time
from datetime import datetime, timedelta, timezone
from io import BytesIO
from zipfile import ZipFile, ZIP_DEFLATED

import paginate
from flask import Flask, render_template, request, jsonify, url_for, redirect, flash, send_file
from google.cloud import firestore

from ca.database import get_db
from ca.forms.CAForm import CAForm
from ca.forms.CertificateForm import CertificateForm
from ca.lib import paginate_link_tag
from ca.models import CA, Certficate
import ca.ca_service as ca_service

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "mina_ca_secret_key_default_1234")

# WTForms select choices를 위한 하위 호환 헬퍼
def get_ca_choices():
    db = get_db()
    docs = db.collection('CAs').stream()
    choices = [('', '상위 CA 없음 (Root CA인 경우)')]
    for doc in docs:
        data = doc.to_dict()
        choices.append((doc.id, f"{data.get('title')} ({data.get('subject', {}).get('common_name')})"))
    return choices

@app.route('/')
def mina_ca_main():
    return redirect(url_for('ca_list'))


@app.route('/login')
def login_page():
    # 로그인 기능을 일단 고려하지 않으므로 곧바로 메인으로 리다이렉트하거나 뷰를 보여줌
    return render_template('login.jinja2')


@app.route("/ca")
def ca_list():
    current_page = request.args.get("page", 1, type=int)
    search_option = request.args.get("search_option", '')
    search_word = request.args.get("search_word", '')

    page_url = url_for("ca_list")
    if search_word:
        page_url = url_for("ca_list", search_option=search_option, search_word=search_word)
        page_url = str(page_url) + "&page=$page"
    else:
        page_url = str(page_url) + "?page=$page"

    items_per_page = 10

    db = get_db()
    query = db.collection('CAs').order_by('created_at', direction=firestore.Query.DESCENDING)
    
    docs = query.stream()
    ca_objects = []
    for doc in docs:
        ca_obj = CA(doc.id, doc.to_dict())
        # 검색 필터 구현
        if search_word and search_option:
            val = getattr(ca_obj, search_option, '')
            if search_word.lower() not in str(val).lower():
                continue
        ca_objects.append(ca_obj)

    total_cnt = len(ca_objects)
    
    # paginate.Page는 list 데이터를 지원함
    paginator = paginate.Page(
        ca_objects,
        page=current_page,
        page_url=page_url,
        items_per_page=items_per_page
    )

    return render_template("ca_list.html", paginator=paginator,
                           paginate_link_tag=paginate_link_tag,
                           page_url=page_url, items_per_page=items_per_page,
                           total_cnt=total_cnt, page=current_page)


@app.route("/ca/add")
def ca_add():
    form = CAForm()
    form.parent_id.choices = get_ca_choices()
    return render_template("ca_add.html", form=form)


@app.route("/ca/add", methods=["POST"])
def ca_add_post():
    ret = {"success": True, "message": ""}
    req_json = request.get_json()

    # 중복 검사 (동일한 타이틀이 있는지 확인)
    db = get_db()
    dup_check = db.collection('CAs').where('title', '==', req_json.get('catitle')).limit(1).get()
    if dup_check:
        return jsonify(success=False, message='이미 등록된 동일한 명칭의 CA가 있습니다.')

    form = CAForm()
    form.parent_id.choices = get_ca_choices()
    
    # request json 데이터를 WTForms 포맷에 맞게 수동 바인딩
    from werkzeug.datastructures import MultiDict
    form = CAForm(MultiDict(req_json))
    form.parent_id.choices = get_ca_choices()

    if form.validate():
        try:
            subject_dict = {
                'country': form.country_name.data,
                'province': form.province_name.data,
                'locality': form.locality_name.data,
                'organization': form.organization_name.data,
                'organizational_unit': form.organizational_unit_name.data,
                'common_name': form.common_name.data,
                'email_address': form.email_address.data,
            }
            
            valid_days = int(form.cadays.data)
            password = form.capass.data
            ca_type = form.catype.data
            parent_id = form.parent_id.data if form.parent_id.data else None
            
            if ca_type == 'ROOT':
                # Root CA 생성 (Self-signed)
                cert_pem, key_pem = ca_service.create_root_ca(
                    subject_dict=subject_dict,
                    password=password,
                    valid_days=valid_days
                )
            else:
                # Intermediate CA 생성
                if not parent_id:
                    return jsonify(success=False, message='Intermediate CA를 생성하려면 상위 CA를 선택해야 합니다.')
                
                # 상위 CA 정보 조회
                parent_ref = db.collection('CAs').document(parent_id).get()
                if not parent_ref.exists:
                    return jsonify(success=False, message='선택한 상위 CA를 찾을 수 없습니다.')
                
                parent_data = parent_ref.to_dict()
                # 상위 CA 복호화를 위해 패스워드 필요 (여기선 편의상 폼의 패스워드와 같거나 혹은 상위 CA 생성 시의 비밀번호를 동적으로 요구해야 함. 본 설계에선 관리 편의를 위해 상위 CA 비밀번호 역시 폼의 capass 값을 임시 매칭하거나 프롬프트 명세대로 서명 처리)
                # 실제 보안성 강화를 위해선 상위 CA 서명 시 상위 키 패스워드를 따로 입력 받아야 하지만, 일단 form.capass로 우선 시도함.
                # (보통 상위 CA의 패스워드는 상위 CA 레코드에 저장하지 않으므로 사용자가 서명 요청 시 입력하는 것이 안전함. ca_add 폼에서는 Intermediate CA의 비밀번호 capass를 입력하므로, 상위 비밀번호는 일단 동일하다고 가정하거나 혹은 추가 필드를 두어야 하나 로그인/단일 관리자 구조 상 동일 키 패스워드 관례로 처리)
                cert_pem, key_pem = ca_service.create_intermediate_ca(
                    subject_dict=subject_dict,
                    password=password,
                    valid_days=valid_days,
                    parent_cert_pem=parent_data.get('certificate_pem'),
                    parent_key_pem=parent_data.get('encrypted_private_key'),
                    parent_password=password # 상위 비밀번호 연동
                )
            
            # Firestore CAs 컬렉션에 저장
            new_ca_ref = db.collection('CAs').document()
            new_ca_ref.set({
                'type': ca_type,
                'parent_id': parent_id,
                'title': form.catitle.data,
                'subject': subject_dict,
                'certificate_pem': cert_pem,
                'encrypted_private_key': key_pem,
                'valid_days': valid_days,
                'created_at': datetime.now(timezone.utc)
            })
            
        except Exception as e:
            logging.exception("CA 생성 중 에러 발생")
            ret["success"] = False
            ret["message"] = f"암호화 라이브러리 연산 실패: {str(e)}"
    else:
        ret["success"] = False
        ret["message"] = "폼 검증 실패: 입력값을 확인하세요."
        
    return jsonify(ret)


@app.route("/ca/<catop>")
def ca_view(catop):
    current_page = request.args.get("page", 1, type=int)
    filter_type = request.args.get('filter_type', 'CERTIFICATED')
    search_option = request.args.get("search_option", '')
    search_word = request.args.get("search_word", '')

    db = get_db()
    ca_ref = db.collection('CAs').document(catop).get()
    if not ca_ref.exists:
        flash('잘못된 CA를 조회하셨습니다.')
        return redirect(url_for('ca_list'))

    ca_record = CA(ca_ref.id, ca_ref.to_dict())

    # 남은 기간 계산
    left_ca_days = (ca_record.created_date + timedelta(days=int(ca_record.cadays))) - datetime.now(timezone.utc)
    left_ca_days = f"{left_ca_days.days} 일"

    # 인증서 필터링
    # Firestore의 Certificates 컬렉션에서 ca_id == catop 조건으로 필터링
    cert_query = db.collection('Certificates').where('ca_id', '==', catop)
    
    docs = cert_query.stream()
    cert_objects = []
    for doc in docs:
        cert_obj = Certficate(doc.id, doc.to_dict())
        
        # filter_type 호환 (CERTIFICATED는 ACTIVE 상태에 매핑됨)
        status_filter = filter_type
        if filter_type == 'CERTIFICATED':
            status_filter = 'ACTIVE'
            
        if cert_obj.to_dict().get('status', 'CSR') != status_filter:
            continue
            
        if search_word and search_option:
            val = getattr(cert_obj, search_option, '')
            if search_word.lower() not in str(val).lower():
                continue
        cert_objects.append(cert_obj)

    total_cnt = len(cert_objects)
    page_url = url_for("ca_view", catop=catop, filter_type=filter_type)
    if search_word:
        page_url = url_for("ca_view", catop=catop, search_option=search_option, search_word=search_word)
        page_url = str(page_url) + "&page=$page"
    else:
        page_url = str(page_url) + "?page=$page"

    items_per_page = 10
    paginator = paginate.Page(
        cert_objects,
        page=current_page,
        page_url=page_url,
        items_per_page=items_per_page
    )

    return render_template("ca_view.html", paginator=paginator,
                           paginate_link_tag=paginate_link_tag,
                           page_url=page_url, items_per_page=items_per_page,
                           total_cnt=total_cnt, page=current_page,
                           ca_record=ca_record, left_ca_days=left_ca_days)


@app.route("/csr/new")
def ca_csr_new():
    form = CertificateForm()
    
    # 사이드바 렌더링용 및 템플릿 호환용 CA 목록 조회
    db = get_db()
    ca_list_refs = db.collection('CAs').order_by('created_at', direction=firestore.Query.DESCENDING).stream()
    from ca.models import CA
    all_cas = [CA(doc.id, doc.to_dict()) for doc in ca_list_refs]
    
    return render_template('ca_csr_new.html', form=form, ca_list_record=all_cas)


@app.route("/csr/new", methods=["POST"])
def cert_csr_new_post():
    db = get_db()
    ret = {"success": True, "message": ""}
    req_json = request.get_json()

    from werkzeug.datastructures import MultiDict
    form = CertificateForm(MultiDict(req_json))

    if form.validate():
        try:
            # SAN 추출 (쉼표로 구분)
            sans_raw = req_json.get('sans', '')
            sans_list = [s.strip() for s in sans_raw.split(',') if s.strip()] if sans_raw else []

            # cryptography 라이브러리를 통해 키 쌍을 만들고 암호화
            private_key = ca_service.generate_private_key()
            encrypted_key_pem = ca_service.serialize_private_key(private_key, form.cert_pass.data)

            # 공개키 추출 및 PEM 직렬화
            from cryptography.hazmat.primitives import serialization as crypto_serialization
            public_key = private_key.public_key()
            public_key_pem = public_key.public_bytes(
                encoding=crypto_serialization.Encoding.PEM,
                format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            subject_dict = {
                'country': form.country_name.data,
                'province': form.province_name.data,
                'locality': form.locality_name.data,
                'organization': form.organization_name.data,
                'organizational_unit': form.organizational_unit_name.data,
                'common_name': form.common_name.data,
                'email_address': form.email_address.data,
            }

            # Firestore Certificates 컬렉션에 적재 (ca_id는 서명 전이므로 None으로 등록)
            cert_ref = db.collection('Certificates').document()
            cert_ref.set({
                'ca_id': None,
                'title': form.cert_title.data,
                'subject': subject_dict,
                'sans': sans_list,
                'certificate_pem': None, # 사인 대기 상태이므로 None
                'encrypted_private_key': encrypted_key_pem,
                'public_key_pem': public_key_pem,
                'valid_days': int(form.cert_days.data),
                'status': 'CSR',
                'revoked_at': None,
                'created_at': datetime.now(timezone.utc)
            })
        except Exception as e:
            logging.exception("CSR 생성 에러")
            ret["success"] = False
            ret["message"] = f"CSR 생성 및 키 발급 실패: {str(e)}"
    else:
        ret["success"] = False
        ret["message"] = "폼 검증 실패"

    return jsonify(ret)


@app.route("/certificate/<cert_id>")
def certificate_view(cert_id):
    db = get_db()
    cert_ref = db.collection('Certificates').document(cert_id).get()
    if not cert_ref.exists:
        flash('인증서가 존재하지 않습니다.')
        return redirect(url_for('ca_list'))

    cert_data = cert_ref.to_dict()
    cert_record = Certficate(cert_ref.id, cert_data)
    
    ca_id = cert_data.get('ca_id')
    ca_record = None
    left_ca_days = None
    if ca_id:
        ca_ref = db.collection('CAs').document(ca_id).get()
        if ca_ref.exists:
            ca_record = CA(ca_ref.id, ca_ref.to_dict())
            left_ca_days = (ca_record.created_date + timedelta(days=int(ca_record.cadays))) - datetime.now(timezone.utc)
            left_ca_days = f"{left_ca_days.days} 일"

    # 사이드바 렌더링용 및 템플릿 호환용 CA 목록 조회
    ca_list_refs = db.collection('CAs').order_by('created_at', direction=firestore.Query.DESCENDING).stream()
    all_cas = [CA(doc.id, doc.to_dict()) for doc in ca_list_refs]

    return render_template("certificate_view.html", ca_record=ca_record, left_ca_days=left_ca_days, 
                           cert_record=cert_record, ca_list_record=all_cas)


@app.route("/certificate/<cert_id>", methods=["DELETE"])
def certificate_delete(cert_id):
    db = get_db()
    cert_ref = db.collection('Certificates').document(cert_id)
    cert_snap = cert_ref.get()
    
    if not cert_snap.exists:
        return jsonify(success=False, message='인증서를 찾을 수 없습니다.')
        
    cert_data = cert_snap.to_dict()
    if cert_data.get('status') == 'CSR':
        cert_ref.delete()
        return jsonify(success=True, message='삭제되었습니다')
    else:
        return jsonify(success=False, message='인증서는 CSR 단계에서만 삭제할 수 있습니다')


@app.route("/certificate/<cert_id>/sign", methods=["POST"])
def certificate_sign(cert_id):
    db = get_db()
    req_data = request.get_json() or {}
    ca_id = req_data.get('ca_id')
    ca_password = req_data.get('capass')

    if not ca_id:
        return jsonify(success=False, message='서명에 사용할 CA를 지정해주세요.')
    if not ca_password:
        return jsonify(success=False, message='CA 비밀키 비밀번호를 입력해주세요.')

    ca_ref = db.collection('CAs').document(ca_id).get()
    if not ca_ref.exists:
        return jsonify(success=False, message='유효하지 않은 서명 CA입니다.')

    ca_data = ca_ref.to_dict()
    cert_ref = db.collection('Certificates').document(cert_id)
    cert_snap = cert_ref.get()
    if not cert_snap.exists:
        return jsonify(success=False, message='인증서를 찾을 수 없습니다.')

    cert_data = cert_snap.to_dict()
    if cert_data.get('status') != 'CSR':
        return jsonify(success=False, message='인증서는 CSR 단계에서만 사인할 수 있습니다')

    try:
        # cryptography 라이브러리로 클라이언트 인증서 사인 수행
        cert_pem = ca_service.create_client_certificate(
            subject_dict=cert_data.get('subject', {}),
            sans=cert_data.get('sans', []),
            valid_days=cert_data.get('valid_days', 365),
            ca_cert_pem=ca_data.get('certificate_pem'),
            ca_key_pem=ca_data.get('encrypted_private_key'),
            ca_password=ca_password,
            client_public_key_pem=cert_data.get('public_key_pem')
        )

        # 상태 업데이트 및 서명 CA 바인딩 완료
        cert_ref.update({
            'ca_id': ca_id,
            'certificate_pem': cert_pem,
            'status': 'ACTIVE',
            'certificate_date': datetime.now(timezone.utc)
        })

        return jsonify(success=True, message='이 인증서를 사인했습니다')
    except Exception as e:
        logging.exception("인증서 서명 중 실패")
        return jsonify(success=False, message=f"서명 작업 실패: {str(e)}")


@app.route("/certificate/<cert_id>/revoke", methods=["POST"])
def certificate_revoke(cert_id):
    db = get_db()
    cert_ref = db.collection('Certificates').document(cert_id)
    cert_snap = cert_ref.get()
    if not cert_snap.exists:
        return jsonify(success=False, message='인증서를 찾을 수 없습니다.')

    cert_data = cert_snap.to_dict()
    if cert_data.get('status') == 'ACTIVE':
        # 단순히 상태값을 REVOKED로 바꾸고 일시 기록
        cert_ref.update({
            'status': 'REVOKED',
            'revoked_at': datetime.now(timezone.utc)
        })
        return jsonify(success=True, message='취소되었습니다')
    else:
        return jsonify(success=False, message='인증서는 ACTIVE 단계에서만 취소할 수 있습니다')


@app.route("/certificate/<cert_id>/download")
def certificate_download(cert_id):
    db = get_db()
    cert_snap = db.collection('Certificates').document(cert_id).get()
    if not cert_snap.exists:
        return '인증서 정보를 찾을 수 없습니다.'
        
    cert_data = cert_snap.to_dict()
    ca_id = cert_data.get('ca_id')
    if not ca_id:
        return '발급된 CA 정보가 연결되어 있지 않습니다'
        
    ca_ref = db.collection('CAs').document(ca_id).get()
    if not ca_ref.exists:
        return '상위 CA를 찾을 수 없습니다'
        
    ca_data = ca_ref.to_dict()
    
    if cert_data.get('status') == 'ACTIVE':
        # 로컬 파일 시스템을 일절 쓰지 않고, 메모리상에서 압축
        zip_file = BytesIO()
        
        with ZipFile(zip_file, 'w', ZIP_DEFLATED) as cert_zip:
            # 클라이언트 인증서
            cert_pem = cert_data.get('certificate_pem')
            cert_zip.writestr(f"{cert_data.get('title')}_cert.pem", cert_pem)
            
            # 클라이언트 개인키 (직접 CSR 업로드 건의 경우 없을 수 있음)
            key_pem = cert_data.get('encrypted_private_key')
            if key_pem:
                if request.args.get('decrypt_key') == 'true':
                    key_password = request.args.get('key_password', '')
                    try:
                        # 사용자가 입력한 패스워드로 개인키 복호화
                        private_key = ca_service.load_private_key(key_pem, key_password)
                        from cryptography.hazmat.primitives import serialization as crypto_serialization
                        unencrypted_key = private_key.private_bytes(
                            encoding=crypto_serialization.Encoding.PEM,
                            format=crypto_serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=crypto_serialization.NoEncryption()
                        ).decode('utf-8')
                        cert_zip.writestr(f"{cert_data.get('title')}_key.pem", unencrypted_key)
                    except Exception as e:
                        # 복호화 실패 시, 다운로드 중단하고 에러 응답
                        return f"개인키 복호화 실패 (비밀번호 확인 요망): {str(e)}", 400
                else:
                    cert_zip.writestr(f"{cert_data.get('title')}_key.pem", key_pem)
            
            # 상위 CA 포함 요청 시
            if request.args.get('ca_include') == 'true':
                ca_cert_pem = ca_data.get('certificate_pem')
                cert_zip.writestr(f"{ca_data.get('title')}_cacert.pem", ca_cert_pem)
                
        zip_file.seek(0)
        
        return send_file(
            zip_file, 
            mimetype="application/zip", 
            as_attachment=True, 
            download_name=f"{cert_data.get('title')}_cert.zip"
        )

    return '잘못된 요청입니다'


@app.context_processor
def mina_processor():
    return dict(
        certificate_status=lambda x: 'active' if request.args.get('filter_type', 'CERTIFICATED') == x else 'link-dark'
    )


# 1. CSR 파일 직접 업로드 API
@app.route("/csr/upload", methods=["POST"])
def csr_upload():
    db = get_db()
    if 'csr_file' not in request.files:
        return jsonify(success=False, message='업로드된 CSR 파일이 없습니다.')
        
    file = request.files['csr_file']
    if file.filename == '':
        return jsonify(success=False, message='선택된 파일이 없습니다.')

    cert_title = request.form.get('cert_title', '').strip()
    valid_days_str = request.form.get('cert_days', '365')
    
    try:
        valid_days = int(valid_days_str)
    except ValueError:
        valid_days = 365
        
    try:
        csr_content = file.read().decode('utf-8')
        
        # ca_service를 통해 CSR 파싱 수행
        subject_dict, sans, public_key_pem = ca_service.load_csr_metadata(csr_content)
        
        if not cert_title:
            cert_title = subject_dict.get('common_name', 'Uploaded CSR')

        # Firestore Certificates 컬렉션에 적재 (무소속 CSR이므로 ca_id = None)
        cert_ref = db.collection('Certificates').document()
        cert_ref.set({
            'ca_id': None,
            'title': cert_title,
            'subject': subject_dict,
            'sans': sans,
            'certificate_pem': None,
            'encrypted_private_key': None,
            'public_key_pem': public_key_pem,
            'valid_days': valid_days,
            'status': 'CSR',
            'revoked_at': None,
            'created_at': datetime.now(timezone.utc)
        })
        
        return jsonify(success=True, message='CSR 파일이 성공적으로 업로드 및 등록되었습니다.')
    except Exception as e:
        logging.exception("CSR 파일 업로드 처리 에러")
        return jsonify(success=False, message=f"CSR 파일 파싱 및 등록 실패: {str(e)}")


# 2. CSR 전용 대기 목록 대시보드
@app.route("/csr/pending")
def csr_pending_list():
    db = get_db()
    # 모든 CAs 목록 읽기 (사이드바 CA 네비게이션 드로어용으로 base 레이아웃이 요구함)
    ca_list_refs = db.collection('CAs').order_by('created_at', direction=firestore.Query.DESCENDING).stream()
    from ca.models import CA
    all_cas = [CA(doc.id, doc.to_dict()) for doc in ca_list_refs]
    
    # status == 'CSR'인 전체 문서 쿼리
    cert_refs = db.collection('Certificates').where('status', '==', 'CSR').stream()
    
    pending_certs = []
    ca_cache = {}
    
    for ref in cert_refs:
        cert_data = ref.to_dict()
        cert_id = ref.id
        from ca.models import Certficate
        cert_record = Certficate(cert_id, cert_data)
        
        ca_id = cert_data.get('ca_id')
        if ca_id not in ca_cache:
            ca_ref = db.collection('CAs').document(ca_id).get()
            if ca_ref.exists:
                ca_cache[ca_id] = CA(ca_ref.id, ca_ref.to_dict())
            else:
                ca_cache[ca_id] = None
        
        ca_record = ca_cache[ca_id]
        pending_certs.append({
            'cert': cert_record,
            'ca': ca_record
        })
        
    return render_template("csr_pending.html", pending_certs=pending_certs, ca_list_record=all_cas)

