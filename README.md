# awsdigger

This tool was created to facilitate the security assessment of IAM resources in AWS environments. It provides a filter languague to look for overprivileged roles, trust relationships and to calculate effective IAM policies.

Futher information https://medium.com/edge-security/abusing-aws-cross-account-relationships-3b36a111b494

This is WIP: 
* It is still under development and it has the minimum functionality. 
* AWS policy syntax is very flexible and therefore it is difficult to support all the "NotAction", "Action", "Deny", "Allow",  different services, resources, conditions, actions and wildcards.
* Managed policies are not supported

# Language

The following clauses are allowed:

* Type
* Effective
* Trusted
* KeyId
* Name
* Arn
* PolicyName
* Action
* Resource
* Condition
* Effect

Operators:

* =
* !=
* =~
* !~
* ~

# Examples:

* Find trust relationships

```
$ python -m awsdigger --filter "Trusted~'arn:aws:iam::123456789012:root'"

$ python -m awsdigger --filter "Action~'sts:AssumeRole' 
```

* Find overprivileged roles

```
$ python -m awsdigger --filter "Action='iam:*' and Resource='*'

$ python -m awsdigger --filter "Effective~'iam:PutUserPolicy' or Effective~'CreateGroup' or Effective~'CreateUser' or Effective~'UpdateGroup' or Effective~'AttachGroupPolicy' "
```
