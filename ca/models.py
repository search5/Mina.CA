import datetime
from slugify import slugify

class FirestoreModel:
    def __init__(self, doc_id, data):
        self.id = doc_id
        self._data = data if data else {}

    def __getattr__(self, name):
        if name in self._data:
            return self._data[name]
        # 일부 SQLAlchemy 하위 호환 필드 매핑
        if name == 'created_date':
            # Firestore의 timestamp는 datetime 객체로 변환되거나 그대로 제공됨
            val = self._data.get('created_at')
            if isinstance(val, (int, float)):
                return datetime.datetime.fromtimestamp(val)
            return val
        if name == 'certificate_date':
            val = self._data.get('certificate_date')
            if isinstance(val, (int, float)):
                return datetime.datetime.fromtimestamp(val)
            return val
        if name == 'revoked_date':
            val = self._data.get('revoked_at')
            if isinstance(val, (int, float)):
                return datetime.datetime.fromtimestamp(val)
            return val
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

    def to_dict(self):
        return self._data

class CA(FirestoreModel):
    @property
    def catitle(self):
        return self._data.get('title', '')

    @property
    def catop(self):
        return self.id

    @property
    def catype(self):
        return self._data.get('type', '')

    @property
    def capass(self):
        return self._data.get('encrypted_private_key', '') # 비밀키 복호화용 패스워드는 메모리에 없으므로 필드값 제공 필요

    @property
    def cadays(self):
        return str(self._data.get('valid_days', ''))

    # DN 필드들 하위 호환 매핑
    @property
    def country_name(self):
        return self._data.get('subject', {}).get('country', '')

    @property
    def province_name(self):
        return self._data.get('subject', {}).get('province', '')

    @property
    def locality_name(self):
        return self._data.get('subject', {}).get('locality', '')

    @property
    def organization_name(self):
        return self._data.get('subject', {}).get('organization', '')

    @property
    def organizational_unit_name(self):
        return self._data.get('subject', {}).get('organizational_unit', '')

    @property
    def common_name(self):
        return self._data.get('subject', {}).get('common_name', '')

    @property
    def email_address(self):
        return self._data.get('subject', {}).get('email_address', '')


class Certficate(FirestoreModel):
    @property
    def cert_title(self):
        return self._data.get('title', '')

    @property
    def cert_status(self):
        # ACTIVE / REVOKED / CSR
        status = self._data.get('status', 'CSR')
        if status == 'ACTIVE':
            return 'CERTIFICATED'
        if status == 'REVOKED':
            return 'REVOKE'
        return status

    @property
    def cert_days(self):
        return str(self._data.get('valid_days', ''))

    @property
    def cert_link(self):
        return slugify(self.cert_title)

    # DN 필드들 하위 호환 매핑
    @property
    def country_name(self):
        return self._data.get('subject', {}).get('country', '')

    @property
    def province_name(self):
        return self._data.get('subject', {}).get('province', '')

    @property
    def locality_name(self):
        return self._data.get('subject', {}).get('locality', '')

    @property
    def organization_name(self):
        return self._data.get('subject', {}).get('organization', '')

    @property
    def organizational_unit_name(self):
        return self._data.get('subject', {}).get('organizational_unit', '')

    @property
    def common_name(self):
        return self._data.get('subject', {}).get('common_name', '')

    @property
    def email_address(self):
        return self._data.get('subject', {}).get('email_address', '')

    @property
    def history(self):
        events = []
        
        # 1. 생성 일시
        created_val = self._data.get('created_at')
        if created_val:
            dt_str = created_val.strftime('%Y-%m-%d %H:%M:%S') if hasattr(created_val, 'strftime') else str(created_val)
            events.append({
                'DATE': dt_str,
                'NOTE': '인증서 서명 요청서(CSR)가 성공적으로 생성 및 등록되었습니다.'
            })
            
        # 2. 발급 일시 (certificate_date 필드가 존재하는 경우)
        issued_val = self._data.get('certificate_date')
        if issued_val:
            dt_str = issued_val.strftime('%Y-%m-%d %H:%M:%S') if hasattr(issued_val, 'strftime') else str(issued_val)
            events.append({
                'DATE': dt_str,
                'NOTE': '상위 인증기관(CA)의 서명 승인이 완료되어 클라이언트 인증서가 활성화되었습니다.'
            })
            
        # 3. 폐기 일시 (revoked_at 필드가 존재하는 경우)
        revoked_val = self._data.get('revoked_at')
        if revoked_val:
            dt_str = revoked_val.strftime('%Y-%m-%d %H:%M:%S') if hasattr(revoked_val, 'strftime') else str(revoked_val)
            events.append({
                'DATE': dt_str,
                'NOTE': '인증서 사용이 정책에 의해 영구적으로 취소(폐기)되었습니다.'
            })
            
        # 날짜 순 정렬 (오름차순)
        events.sort(key=lambda x: x['DATE'])
        return events
