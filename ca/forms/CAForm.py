from wtforms import Form, StringField, validators


class CAForm(Form):
    # last_name  = StringField(u'Last Name', validators=[validators.optional()])
    catitle = StringField('인증기관명', validators=[validators.input_required()])
    catop = StringField('CA 디렉터리', validators=[validators.input_required()])
    cakey = StringField('CA 비밀키 파일명', validators=[validators.input_required()])
    careq = StringField('CA 인증 요청서 파일명', validators=[validators.input_required()])
    cacert = StringField('CA 인증기관 파일명', validators=[validators.input_required()])
    cadays = StringField('인증기관 유효기간(일단위)', validators=[validators.input_required()])
