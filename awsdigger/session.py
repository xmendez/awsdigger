# session.py

from .filter import Filter

import os
import boto3
import sys
import getopt
import _pickle as pickle
import gzip
import os.path

import threading
from queue import Queue

iam_actions = [
    "iam:ResetServiceSpecificCredential",
    "iam:UpdateServiceSpecificCredential",
    "iam:EnableMFADevice",
    "iam:ListUsers",
    "iam:CreateServiceLinkedRole",
    "iam:ListRolePolicies",
    "iam:PutRolePolicy",
    "iam:DeleteAccountPasswordPolicy",
    "iam:ListSSHPublicKeys",
    "iam:ListAttachedUserPolicies",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
    "iam:ListEntitiesForPolicy",
    "iam:DeleteServiceLinkedRole",
    "iam:ListServerCertificates",
    "iam:ListAccountAliases",
    "iam:PassRole",
    "iam:GetContextKeysForCustomPolicy",
    "iam:ListInstanceProfiles",
    "iam:ListMFADevices",
    "iam:UploadSigningCertificate",
    "iam:DeleteRole",
    "iam:SimulateCustomPolicy",
    "iam:CreateServiceSpecificCredential",
    "iam:UpdateRoleDescription",
    "iam:ResyncMFADevice",
    "iam:AttachGroupPolicy",
    "iam:ListAttachedRolePolicies",
    "iam:ListPoliciesGrantingServiceAccess",
    "iam:GetInstanceProfile",
    "iam:UpdateAccessKey",
    "iam:AddClientIDToOpenIDConnectProvider",
    "iam:ListGroupPolicies",
    "iam:DeleteOpenIDConnectProvider",
    "iam:CreateInstanceProfile",
    "iam:PutUserPolicy",
    "iam:ChangePassword",
    "iam:GenerateServiceLastAccessedDetails"
    "iam:CreateOpenIDConnectProvider",
    "iam:GetOpenIDConnectProvider",
    "iam:DeleteGroup",
    "iam:DeleteRolePolicy",
    "iam:ListServiceSpecificCredentials",
    "iam:ListRoles",
    "iam:CreateSAMLProvider",
    "iam:ListPolicyVersions",
    "iam:DeleteSSHPublicKey",
    "iam:CreateGroup",
    "iam:CreateUser",
    "iam:ListAccessKeys",
    "iam:UploadServerCertificate",
    "iam:GetRole",
    "iam:UploadSSHPublicKey",
    "iam:RemoveRoleFromInstanceProfile",
    "iam:UpdateSigningCertificate",
    "iam:DeleteLoginProfile",
    "iam:UpdateUser",
    "iam:ListVirtualMFADevices",
    "iam:GetSAMLProvider",
    "iam:AttachRolePolicy",
    "iam:UpdateAccountPasswordPolicy",
    "iam:CreatePolicy",
    "iam:DeleteServiceSpecificCredential",
    "iam:GetServiceLinkedRoleDeletionStatus",
    "iam:GetGroupPolicy",
    "iam:GetServiceLastAccessedDetailsWithEntities",
    "iam:DetachUserPolicy",
    "iam:GetLoginProfile",
    "iam:DeleteUserPolicy",
    "iam:UpdateLoginProfile",
    "iam:GetPolicyVersion",
    "iam:AddRoleToInstanceProfile",
    "iam:UpdateServerCertificate",
    "iam:DeactivateMFADevice",
    "iam:GetAccountPasswordPolicy",
    "iam:GetUser",
    "iam:DeleteVirtualMFADevice",
    "iam:DeletePolicyVersion",
    "iam:GetServiceLastAccessedDetails",
    "iam:RemoveUserFromGroup",
    "iam:AttachUserPolicy",
    "iam:UpdateOpenIDConnectProviderThumbprint",
    "iam:GetAccessKeyLastUsed",
    "iam:DeleteGroupPolicy",
    "iam:DeleteAccountAlias",
    "iam:GetGroup",
    "iam:UpdateSSHPublicKey",
    "iam:CreateAccessKey",
    "iam:DetachRolePolicy",
    "iam:GetSSHPublicKey",
    "iam:ListAttachedGroupPolicies",
    "iam:CreateAccountAlias",
    "iam:DeleteSigningCertificate",
    "iam:ListGroupsForUser",
    "iam:ListOpenIDConnectProviders",
    "iam:UpdateSAMLProvider",
    "iam:ListInstanceProfilesForRole",
    "iam:CreateVirtualMFADevice",
    "iam:ListGroups",
    "iam:DeleteUser",
    "iam:GetAccountAuthorizationDetails",
    "iam:DeletePolicy",
    "iam:ListSigningCertificates",
    "iam:PutGroupPolicy",
    "iam:RemoveClientIDFromOpenIDConnectProvider",
    "iam:ListPolicies",
    "iam:GetContextKeysForPrincipalPolicy",
    "iam:GenerateCredentialReport",
    "iam:SetDefaultPolicyVersion",
    "iam:CreateRole",
    "iam:CreatePolicyVersion",
    "iam:GetAccountSummary",
    "iam:GetServerCertificate",
    "iam:DetachGroupPolicy",
    "iam:DeleteSAMLProvider",
    "iam:GetUserPolicy",
    "iam:GetCredentialReport",
    "iam:DeleteAccessKey",
    "iam:DeleteServerCertificate",
    "iam:ListUserPolicies",
    "iam:ListSAMLProviders",
    "iam:GetRolePolicy",
    "iam:DeleteInstanceProfile",
    "iam:CreateLoginProfile",
    "iam:SimulatePrincipalPolicy",
    "iam:UpdateGroup",
    "iam:GetPolicy"
]

help_msg = """
usage: %s
    -h: This help
    --filter <exp>: Look for the indicated role
""" % sys.argv[0]


class Walker:
    def __init__(self, options):
        self.options = options

    def get_walker_prop(self):
        return [
            {
                '_type': 'roles',
                'list': 'list_roles',
                'name': 'RoleName',
                'id': 'RoleName',
                'list_policies': 'list_role_policies',
                'get_policy': 'get_role_policy',
            },
            {
                '_type': 'groups',
                'list': 'list_groups',
                'name': 'GroupName',
                'id': 'GroupName',
                'list_policies': 'list_group_policies',
                'get_policy': 'get_group_policy',
            },
            {
                '_type': 'users',
                'list': 'list_users',
                'name': 'UserName',
                'id': 'UserId',
                'list_policies': 'list_user_policies',
                'get_policy': 'get_user_policy',
            }
        ]

    def get_iam_actions(self, string, difference=False):
        ret = []
        wildcard = string.find("*")

        if wildcard > 0:
            ret = [iam for iam in iam_actions if iam.startswith(string[:wildcard])]
        elif wildcard == 0:
            ret = iam_actions
        elif string in iam_actions:
            ret = [string]

        if difference:
            return list(set(iam_actions).difference(set(ret)))

        return ret

    def get_effective_policy(self, my_item):
        def compute_statement(statement, allow, deny):
            resource = statement.get('Resource', '')

            if isinstance(resource, list):
                if '*' not in resource and not any(map(lambda a: a.startswith('arn:aws:iam::'), resource)):
                    return []
            else:
                if resource != '*' and not resource.startswith('arn:aws:iam::'):
                    return []

            condition_keys = [key for key_list in [cond[1].keys() for cond in statement.get('Condition', {}).items()] for key in key_list]
            if 'aws:MultiFactorAuthAge' in condition_keys and len(statement.get('Condition', {}).items()) > 1:
                return []
            elif 'aws:MultiFactorAuthAge' not in condition_keys and len(statement.get('Condition', {}).items()) > 0:
                return []

            action_list = statement.get('Action', []) if isinstance(statement.get('Action', []), list) else [statement.get('Action', "")]
            not_action_list = statement.get('NotAction', []) if isinstance(statement.get('NotAction', []), list) else [statement.get('NotAction', "")]
            if statement.get('Effect', '') == 'Allow':
                for action in filter(lambda a: a.startswith('iam:') or a == '*', action_list):
                    allow += self.get_iam_actions(action)
                for action in not_action_list:
                    allow += self.get_iam_actions(action, True)
            elif statement.get('Effect', '') == 'Deny':
                for action in filter(lambda a: a.startswith('iam:') or a == '*', action_list):
                    deny += self.get_iam_actions(action)
                for action in not_action_list:
                    deny += self.get_iam_actions(action, True)
            else:
                raise Exception('Unknown Effect in statement')

        allow = []
        deny = []
        for policy in my_item['Policies']:
            statement = policy.get('PolicyDocument', {}).get('Statement', [])

            if isinstance(statement, list):
                for statement in statement:
                    compute_statement(statement, allow, deny)
            else:
                compute_statement(statement, allow, deny)

        return list(set(allow).difference(set(deny)))

    def rip_role(self, item, props):
        client = boto3.client('iam')
        my_item = {
            'Name': item[props['name']],
            'Arn': item['Arn'],
            'Policies': [],
            'KeyId': [],
            'Effective': [],
            'Trusted': [],
            '_type': props['_type']
        }

        if 'AssumeRolePolicyDocument' in item:
            for principal in [i['Principal'] for i in item['AssumeRolePolicyDocument']['Statement'] if i['Effect'] == 'Allow']:
                for val in principal.values():
                    if isinstance(val, list):
                        my_item['Trusted'] += val
                    else:
                        my_item['Trusted'].append(val)

        if props['_type'] == 'users':
            # List access keys through the pagination interface.
            paginator = client.get_paginator('list_access_keys')
            for response in paginator.paginate(UserName=my_item['Name']):
                for keyinfo in response['AccessKeyMetadata']:
                    my_item['KeyId'].append(keyinfo['AccessKeyId'])

        inner_paginator = client.get_paginator(props["list_policies"])
        for inner_page in inner_paginator.paginate(**dict([(props['name'], item[props['name']])])).result_key_iters():
            for item_policy_name in inner_page:
                my_item['Policies'].append({
                        'PolicyName': item_policy_name,
                        'PolicyDocument': getattr(client, props['get_policy'])
                                                 (**dict([(props['name'], item[props['name']]), ('PolicyName', item_policy_name)]))['PolicyDocument']
                    })

        my_item['Effective'] = self.get_effective_policy(my_item)

        return my_item

    def get_walker_items_nocache(self):
        client = boto3.client('iam')

        for props in self.get_walker_prop():
            if self.options.get('verbose', False):
                print("Digging current AWS {}...".format(props.get('_type')))

            paginator = client.get_paginator(props["list"])
            for page in paginator.paginate().result_key_iters():
                for item in page:
                    yield self.rip_role(item, props)

    def get_walker_items_nocache_threaded(self):
        def get_walker_items_thread(props, queue):
            client = boto3.client('iam')

            paginator = client.get_paginator(props["list"])
            for page in paginator.paginate().result_key_iters():
                for item in page:
                    queue.put(self.rip_role(item, props))

            queue.put(None)

        thread_list = []
        queue = Queue()

        for props in self.get_walker_prop():
            if self.options.get('verbose', False):
                print("Digging current AWS {}...".format(props.get('_type')))
            th = threading.Thread(target=get_walker_items_thread, args=(props, queue))
            thread_list.append(th)
            th.start()

        num_workers = len(thread_list)

        while 1:
            item = queue.get()

            if item is None:
                num_workers -= 1
            else:
                yield item

            if num_workers <= 0:
                break

        for th in thread_list:
            th.join()

    def get_walker_items(self, cache=True):
        if cache:
            return self.get_walker_items_cache()
        else:
            return self.get_walker_items_nocache_threaded()

    def get_walker_items_cache(self):
        my_cache = self.options['cache']
        use_cache = my_cache is not None and os.path.exists(my_cache) and os.path.isfile(my_cache)
        output_fn = None

        if use_cache and my_cache is not None:
            try:
                with gzip.open(my_cache, 'r+b') as output:
                    while 1:
                        item = pickle.load(output)
                        yield item
            except EOFError:
                raise StopIteration
        else:
            output_fn = None
            if my_cache is not None:
                try:
                    output_fn = gzip.open(my_cache, 'w+b')
                except IOError:
                    print("Error open {} for writing cache".format(my_cache))
                    output_fn = None

            # for role in self.get_walker_items_nocache():
            for role in self.get_walker_items_nocache_threaded():
                if output_fn is not None:
                    pickle.dump(role, output_fn)
                yield role


class Session:
    def __init__(self, options=None):
        self.options = {
            'filter': None,
            'cache': None,
            'type': "roles",
            'onlytrusted': False,
            'verbose': False
        }

        if options is not None:
            self.options.update(options)

    @staticmethod
    def parse_cli():
        try:
            opts, args = getopt.getopt(sys.argv[1:], 'h', ['filter=', 'verbose', 'dump', 'cache=', 'type=', 'onlytrusted'])
        except getopt.error as msg:
            sys.stdout = sys.stderr
            print(help_msg)
            print(msg)
            sys.exit(2)

        my_session = Session()

        for opt, value in opts:
            if opt == '-h':
                print(help_msg)
                sys.exit(2)
            if opt == '--filter':
                my_session.options['filter'] = Filter(value)
            elif opt == '--cache':
                my_session.options['cache'] = value
            elif opt == '--verbose':
                my_session.options['verbose'] = True
            elif opt == '--onlytrusted':
                my_session.options['onlytrusted'] = True
            elif opt == '--type':
                if value not in ['groups', 'roles', 'users']:
                    raise Exception("Incorrect type value!")

                my_session.options['type'] = value

        if not my_session.validate():
            sys.stdout = sys.stderr
            print(help_msg)
            sys.exit(2)

        return my_session

    def validate(self):
        if self.options.get('filter') is None:
            return False

        return True

    def dig(self, **kwargs):
        self.options.update(kwargs)

        role_walk = Walker(self.options)

        for item in role_walk.get_walker_items():
            res = []
            for policy in item['Policies']:
                if isinstance(policy['PolicyDocument']['Statement'], list):
                    for statement in policy['PolicyDocument']['Statement']:
                        statement['visible'] = self.options['filter'].is_visible(item, statement)
                        res.append(statement['visible'])
                else:
                    statement = policy['PolicyDocument']['Statement']
                    statement['visible'] = self.options['filter'].is_visible(item, statement)
                    res.append(statement['visible'])
            else:
                if self.options['filter'].is_visible(item, []):
                    res.append(True)

            if any(res):
                yield item
