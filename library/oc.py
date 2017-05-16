#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2017, Kenneth D. Evensen <kevensen@redhat.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = """
module: oc
author:
- "Kenneth D. Evensen (@kevensen)"
short_description: Manage OpenShift Resources
description:
- This module allows management of resources in an OpenShift cluster.  This module gets executed on an OpenShift master and uses the system:admin's .kubeconfig file typically located at /root/.kube/config.  By default, this module uses the first (often the only) cluster entry under the "clusters" entry.  Thus, no API endpoint is required.

This is a self contained module and has no external dependencies.
version_added: "2.3"
options:
  kind:
    required: true
    description:
      - The kind of the resource upon which to take action.
"""

EXAMPLES = """

"""

RETURN = '''

...
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import BOOLEANS_TRUE
from ansible.module_utils.pycompat24 import get_exception
from itertools import chain
from collections import defaultdict
import ast
import base64
import json
import os
import requests
import yaml

class KubeConfig(object):
    def __init__(self, path, host, ansible):
        yml = []
        self.path = path
        self.host = host
        self.ansible = ansible
        with open(path, 'r') as stream:
            try:
                config = yaml.load(stream)
                if not host:
                    self.cluster = config['clusters'][0]
                    self.host = self.cluster['cluster']['server']
                else:
                    self.cluster = self.parse_cluster_data(config['clusters'], host)

                self.api_version = self.cluster['cluster']['api-version']
                self.ca = self.cluster['cluster']['certificate-authority-data']
                self.server = self.cluster['cluster']['server']
                self.name = self.cluster['name']

                self.parse_user_data(config['users'])

                self.client_cert_file = '/tmp/' + self.name + '-cert.pem'
                self.client_key_file = '/tmp/' + self.name + '-key.pem'
                self.ca_file = '/tmp/' + self.name + '-ca-cert.pem'
                self.write_file(self.client_cert_file, self.client_cert)
                self.write_file(self.client_key_file, self.client_key)
                self.write_file(self.ca_file, self.ca)
            except yaml.YAMLError as exc:
                self.ansible.fail_json(msg='Unable to parse config file %s' % path)

    def parse_cluster_data(self, clusters, host):
        for cluster in clusters:
            if host == cluster['cluster']['server']:
                return cluster
        self.ansible.fail_json(msg='Unable to find cluster %s in kube config file' % host)

    def parse_user_data(self, users):
        for user in users:
            name = user['name'].split('/')[1]
            if name == self.name:
                self.client_cert = user['user']['client-certificate-data']
                self.client_key = user['user']['client-key-data']
                return
        self.ansible.fail_json(msg='Can not parse client certificate data out of config file %s.' % self.path)

    def write_file(self, file_name, cert_string):
        self.ansible.log("Writing temporary file %s" % file_name)
        f = open(file_name, 'w')
        f.write(base64.standard_b64decode(cert_string))
        f.close()

    def clean(self):
        os.remove(self.client_key_file)
        os.remove(self.client_cert_file)
        os.remove(self.ca_file)

class OC(object):
    def __init__(self, kube_config, module):
        self.apis = ['api', 'oapi']
        self.kube_config = kube_config
        self.module = module
        self.kinds = {}

    def build_facts(self):
        for api in self.apis:
            url = self.kube_config.host + "/" + api + "/v1"
            response = requests.get(url, cert=(self.kube_config.client_cert_file,
                                               self.kube_config.client_key_file),
                                         verify=self.kube_config.ca_file).json()
            for resource in response['resources']:
                self.kinds[resource['kind']] = {'kind': resource['kind'],
                                                'name': resource['name'].split('/')[0],
                                                'namespaced': resource['namespaced'],
                                                'api': api,
                                                'version': 'v1',
                                                'baseurl': url
                                                }

    def build_url(self, kind, name = None, namespace = None):
        url = self.kinds[kind]['baseurl']
        if self.kinds[kind]['namespaced'] == True:
            url += '/namespaces/'
            if namespace is None:
                self.module.fail_json(msg='Kind %s requires a namespace.  None provided' % kind)
            url += namespace

        url += '/'
        url += self.kinds[kind]['name']

        if name is not None:
            url += '/'
            url += name

        return url

    def get_resource(self, kind, namespace = None, name = None, uniqueify = True):
        url = ''
        if name is not None:
            url = self.build_url(kind, namespace=namespace, name=name)
        elif namespace is not None:
            url = self.build_url(kind, namespace=namespace)
        else:
            url = self.build_url(kind)

        resource = None
        response = requests.get(url, cert=(self.kube_config.client_cert_file,
                                           self.kube_config.client_key_file),
                                     verify=self.kube_config.ca_file)

        if response.json() is not None and response.json() != {}:
            if response.json()['kind'] == 'Status' and response.json()['metadata'] == {}:
                return None

        if response.status_code == 404:
            return None
        if uniqueify:
            return self.uniqueify(response.json())

        return response.json()

    def create_resource(self, kind, namespace, name, inline):
        url = ''
        changed = False

        if namespace is not None:
            url = self.build_url(kind, namespace=namespace)
        else:
            url = self.build_url(kind)

        self.module.log(msg="URL for create request is %s" % url)

        inline['kind'] = kind
        inline['apiVersion'] = self.kinds[kind]['version']

        self.module.log(msg="JSON body for create request is %s" % json.dumps(inline))

        response = requests.post(url, data=json.dumps(inline),
                                      cert=(self.kube_config.client_cert_file,
                                            self.kube_config.client_key_file),
                                      verify=self.kube_config.ca_file)

        self.module.log(msg="Response for create request is %s" % str(response.json()))

        if response.status_code == 404:
            return None, changed
        elif response.status_code == 409:
            return response.json(), changed
        elif response.status_code >= 300:
            self.module.fail_json(msg='Failed to create resource %s in namespace %s with msg %s' % (name, namespace, response.reason))
        else:
            changed = True
            return response.json(), changed

    def replace_resource(self, kind, namespace, name, inline):
        resource = self.get_resource(kind=kind,
                                     namespace=namespace,
                                     name=name,
                                     uniqueify=True)
        return resource, False

    def delete_resource(self, kind, namespace = None, name = None):
        url = ''
        changed = False
        if namespace is not None:
            url = self.build_url(kind, namespace=namespace, name=name)
        else:
            url = self.build_url(kind, name=name)

        response = requests.delete(url, cert=(self.kube_config.client_cert_file,
                                           self.kube_config.client_key_file),
                                     verify=self.kube_config.ca_file)

        if response.status_code == 404:
            return None, changed
        elif response.status_code >= 300:
            self.module.fail_json(msg='Failed to delete resource %s in namespace %s with msg %s' % (name, namespace, response.msg))
        else:
            changed = True
            return response.json(), changed

    def uniqueify(self, resource):
        try:
            del resource['metadata']['creationTimestamp']
            del resource['metadata']['resourceVersion']
            del resource['metadata']['uid']
        except KeyError:
            pass
        return resource

def main():

    module = AnsibleModule(
        argument_spec=dict(
            force=dict(default=False, type='bool'),
            host=dict(required=False, type='str'),
            inline=dict(required=False, type='dict'),
            kind=dict(required=False, type='str'),
            name=dict(required=False, type='str'),
            namespace=dict(required=False, type='str'),

            path=dict(required=False, default='/root/.kube/config', type='str'),
            state=dict(required=True,
                       choices=['present', 'absent', 'get']),
            uniqueify=dict(default=True, type='bool')
        ),
        mutually_exclusive=(['name', 'inline'],
                            ['namespace', 'inline'],
        ),
        required_if=([['state', 'absent', ['kind']],
                      ['state', 'present',['inline']]]
        ),
        required_one_of=([['kind', 'inline']]),
        no_log=False,
        supports_check_mode=True
    )
    kind = None
    inline = None
    name = None
    namespace = None

    check_mode = module.check_mode
    force = module.params['force']
    host = module.params['host']
    inline = module.params['inline']
    path = module.params['path']
    state = module.params['state']
    uniqueify = module.params['uniqueify']

    if inline is None:
        kind = module.params['kind'].capitalize()
        name = module.params['name']
        namespace = module.params['namespace']
    else:
        kind = inline['kind']
        try:
            name = inline['metadata']['name']
        except KeyError:
            pass
        try:
            namespace = inline['metadata']['namespace']
        except KeyError:
            pass

    facts = {}
    resource = None
    kube_config = KubeConfig(path, host, module)
    oc = OC(kube_config, module)
    oc.build_facts()
    changed = False

    resource = oc.get_resource(kind=kind,
                               namespace=namespace,
                               name=name,
                               uniqueify=uniqueify)

    if state == 'present' and resource is None:
        resource, changed = oc.create_resource(kind=kind,
                                               namespace=namespace,
                                               name=name,
                                               inline=inline)
    elif state == 'present' and resource is not None:
        resource, changed = oc.replace_resource(kind=kind,
                                                namespace=namespace,
                                                name=name,
                                                inline=inline)
    elif state == 'absent' and resource is not None:
        resource, changed = oc.delete_resource(kind=kind,
                                               namespace=namespace,
                                               name=name)
    facts['oc'] = {'resources': resource,
                   'url': oc.build_url(kind=kind,
                                       namespace=namespace,
                                       name=name),
                   'uniquified': uniqueify}
    kube_config.clean()
    module.exit_json(changed=changed, ansible_facts=facts)

if __name__ == '__main__':
    main()
