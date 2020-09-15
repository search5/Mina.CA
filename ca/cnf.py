import configparser
from io import StringIO


class OpenSSLCnf:
    def __init__(self, cn):
        # todo database load cn
        self.cnf = configparser.ConfigParser(allow_no_value=True)
        self.cnf.optionxform = str
        self.default_ca_name = None
        self.req_extension = None
        # todo database result into self.cnf
        # self.cnf.read_string(db)

    def add_ca(self, ca_name):
        self.cnf.add_section('ca')
        self.cnf.set('ca', 'default_ca', ca_name)

        self.default_ca_name = ca_name

    def add_ca_info(self, name, value=None):
        if not self.cnf.has_section(self.default_ca_name):
            self.cnf.add_section(self.default_ca_name)

        if type(name) == str:
            self.cnf.set(self.default_ca_name, name, value)
        elif type(name) == dict:
            for si, sv in name.items():
                self.cnf.set(self.default_ca_name, si, sv)
        elif type(name) == tuple:
            self.cnf.set(self.default_ca_name, name[0], name[1])
        else:
            raise ValueError()

    def export(self):
        if not self.is_valid:
            return "openssl.cnf validation failed"
        export_io = StringIO()
        self.cnf.write(export_io)
        return export_io.getvalue()

    def add_policy(self, policy_name, policy_value=None):
        if not self.cnf.has_section('policy'):
            self.cnf.add_section('policy')

        self.cnt_set('policy', policy_name, policy_value)

    def add_req(self, req_name, req_value=None):
        if not self.cnf.has_section('req'):
            self.cnf.add_section('req')

        self.cnt_set('req', req_name, req_value)

    def add_distinguished_name(self, distinguished_name, distinguished_value=None):
        if not self.cnf.has_section('req_distinguished_name'):
            self.cnf.add_section('req_distinguished_name')

        self.cnt_set('req_distinguished_name', distinguished_name, distinguished_value)

    def add_distinguished_default(self, distinguished_name, distinguished_value=None):
        if not self.cnf.has_section('req_distinguished_name'):
            self.cnf.add_section('req_distinguished_name')

        self.cnt_set('req_distinguished_name', distinguished_name, distinguished_value, default_check=True)

    def cnt_set(self, section_name, item_name, item_value, default_check=False):
        if type(item_name) == str:
            self.cnf.set(section_name, f"{item_name}_default" if default_check else item_name, item_value)
        elif type(item_name) == dict:
            for si, sv in item_name.items():
                self.cnf.set(section_name, f"{si}_default" if default_check else si, sv)
        elif type(item_name) == tuple:
            self.cnf.set(section_name, f"{item_name[0]}_default" if default_check else item_name[0], item_name[1])
        else:
            raise ValueError()

    def add_extension(self, extension_name, key, value):
        if not self.cnf.has_section(extension_name):
            self.cnf.add_section(extension_name)

        self.cnt_set(extension_name, key, value)

    def add_req_attribute(self, attribute_name, attribute_value=None):
        if not self.cnf.has_section('req_attributes'):
            self.cnf.add_section('req_attributes')

        self.cnt_set('req_attributes', attribute_name, attribute_value)

        self.add_req('attributes', 'req_attributes')

    def add_challenge_password(self, value, min=0, max=0):
        self.add_req_attribute('challengePassword', value)
        if min:
            self.add_req_attribute('challengePassword_min', min)
        if max:
            self.add_req_attribute('challengePassword_max', max)

    def add_input_password(self, password):
        self.add_req("input_password", password)

    def add_output_password(self, password):
        self.add_req("output_password", password)

    def add_alt_names(self, *alt_names):
        if not self.req_extension:
            raise ValueError('The extension of the certification request was not specified.')

        if not self.cnf.has_section(self.req_extension):
            self.cnf.add_section(self.req_extension)

        self.cnf.set(self.req_extension, 'subjectAltName', '@alt_names')

        if not self.cnf.has_section('alt_names'):
            self.cnf.add_section('alt_names')

        for idx, item in enumerate(alt_names, 1):
            self.cnf.set(f'DNS.{idx}', item)

        self.add_req('req_extensions', self.req_extension)

    @property
    def is_valid(self):
        return True


if __name__ == '__main__':
    a = OpenSSLCnf('root')
    a.add_ca('CA_default')
    a.add_ca_info('dir', '/root/ca')
    a.add_ca_info(dict(certs="$dir/certs", RANDFILE="$dir/private/.rand"))
    a.add_ca_info(('crl_dir', '$dir/crl'))
    a.add_distinguished_default('countryName', 'KR')
    a.add_extension('server_cert', 'basicConstraints', 'CA:FALSE')
    a.add_extension('server_cert', "nsComment", "\"OpenSSL Generated Server Certificate\"")
    a.add_extension('server_cert', "keyUsage", "critical, digitalSignature, keyEncipherment")
    print(a.export())
