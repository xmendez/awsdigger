# awsdigger.py

from .session import Session

import os
import sys
import pprint

pp = pprint.PrettyPrinter(indent=4)


def print_item(item, session):
    verbose = session['verbose']

    print("\n* Type: {} Name: {}".format(item['_type'], item['Name']))

    if len(item.get('Trusted', [])) > 0:
        print("* Trusted relationships:")
        for trusted in item.get('Trusted', []):
            print("\t+ {}".format(trusted))

    if verbose:
        print("* Effective IAM permissions:")

        for eff in sorted(item['Effective']):
            print("\t+ {}".format(eff))

    if not session['onlytrusted']:
        print("* Matched policies:")
        for policy in item['Policies']:
            if isinstance(policy['PolicyDocument']['Statement'], list):
                for p in policy['PolicyDocument']['Statement']:
                    if p['visible']:
                        print("+ Policy: {}".format(policy['PolicyName']))
                        pp.pprint(p)
                    elif verbose:
                        print("- Policy: {}".format(policy['PolicyName']))
                        pp.pprint(p)
            else:
                if policy['PolicyDocument']['Statement']['visible'] is True:
                    print("+ Policy: {}".format(policy['PolicyName']))
                    pp.pprint(policy['PolicyDocument']['Statement'])
                elif verbose:
                    print("- Policy: {}".format(policy['PolicyName']))
                    pp.pprint(policy['PolicyDocument']['Statement'])


def main():
    my_session = Session().parse_cli()

    for item in my_session.dig():
        print_item(item, my_session.options)

if __name__ == '__main__':
    main()
