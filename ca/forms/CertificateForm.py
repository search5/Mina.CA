from wtforms import Form, StringField, validators, PasswordField, SelectField


class CertificateForm(Form):
    cert_title = StringField('인증 서비스명(한글)', validators=[validators.input_required()])
    cert_pass = PasswordField('인증키 비밀번호', validators=[validators.input_required()])
    country_name = StringField('Country Name', validators=[validators.optional()], description='2자리 국가코드')
    province_name = StringField('State or Province Name', validators=[validators.optional()], description='시/도')
    locality_name = StringField('Locality Name', validators=[validators.optional()], description='구/군/시')
    organization_name = StringField('Organization Name', validators=[validators.optional()], description='회사명')
    organizational_unit_name = StringField('Organizational Unit Name', validators=[validators.optional()], description='부서명')
    common_name = StringField('Common Name', validators=[validators.optional()], description='도메인명')
    email_address = StringField('Email Address', validators=[validators.optional()], description='담당자 이메일')
    cert_days = StringField('인증서 유효기간(일단위)', validators=[validators.input_required()])
