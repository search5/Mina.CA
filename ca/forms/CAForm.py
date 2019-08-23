from wtforms import Form, StringField, validators, PasswordField, SelectField


class CAForm(Form):
    catitle = StringField('인증기관명(한글)', validators=[validators.input_required()])
    catop = StringField('CA 디렉터리', validators=[validators.input_required()])
    catype = SelectField('CA 타입', validators=[validators.input_required()], choices=(('ROOT', 'Root'), ('INTERMEDIATE', 'Intermediate')))
    capass = PasswordField('CA 비밀키', validators=[validators.input_required()])
    country_name = StringField('Country Name', validators=[validators.optional()], description='2자리 국가코드')
    province_name = StringField('State or Province Name', validators=[validators.optional()], description='시/도')
    locality_name = StringField('Locality Name', validators=[validators.optional()], description='구/군/시')
    organization_name = StringField('Organization Name', validators=[validators.optional()], description='회사명')
    organizational_unit_name = StringField('Organizational Unit Name', validators=[validators.optional()], description='부서명')
    common_name = StringField('Common Name', validators=[validators.optional()], description='도메인명')
    email_address = StringField('Email Address', validators=[validators.optional()], description='담당자 이메일')
    cadays = StringField('인증기관 유효기간(일단위)', validators=[validators.input_required()])
