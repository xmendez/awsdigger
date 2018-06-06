import re
from pyparsing import QuotedString, oneOf, Group, Optional, ZeroOrMore, Suppress, ParseException, delimitedList, printables, Word


class Filter:
    def __init__(self, filter_string):
        self.filter_string = filter_string

        quoted_str_value = QuotedString('\'', unquoteResults=True, escChar='\\')
        #quoted_str_value = delimitedList(Word(printables, excludeChars=','))
        operator = oneOf("and or")
        not_operator = Optional(oneOf("not"), "notpresent")


        statement_symbols = oneOf("Type Effective Trusted KeyId Name Arn PolicyName Action Resource Condition Effect").setParseAction(self.__compute_statement_symbol)

        definition = Group(statement_symbols + oneOf("= != =~ !~ ~") + quoted_str_value).setParseAction(self.__compute_expr)

        definition_not = not_operator + definition
        definition_expr = definition_not + ZeroOrMore(operator + definition_not)
        nested_definition = Group(Suppress("(") + definition_expr + Suppress(")"))
        nested_definition_not = not_operator + nested_definition

        self.finalformula = (nested_definition_not ^ definition_expr) + ZeroOrMore(operator + (nested_definition_not ^ definition_expr))

        definition_not.setParseAction(self.__compute_not_operator)
        nested_definition_not.setParseAction(self.__compute_not_operator)
        nested_definition.setParseAction(self.__compute_formula)
        self.finalformula.setParseAction(self.__myreduce)

    def __compute_expr(self, tokens):
        leftvalue, operator, rightvalue = tokens[0]

        if operator == "=":
            if isinstance(leftvalue, list):
                return any(map(lambda a: a == rightvalue, leftvalue))
            else:
                return leftvalue == rightvalue
        elif operator == "!=":
            if isinstance(leftvalue, list):
                return any(map(lambda a: a != rightvalue, leftvalue))
            else:
                return leftvalue != rightvalue
        elif operator == "=~":
            regex = re.compile(rightvalue, re.MULTILINE | re.DOTALL)
            if isinstance(leftvalue, list):
                return any(map(lambda a: regex.search(a) is not None, leftvalue))
            else:
                return regex.search(leftvalue) is not None
        elif operator == "!~":
            if isinstance(leftvalue, list):
                return any(map(lambda a: rightvalue.lower() not in a.lower(), leftvalue))
            else:
                return rightvalue.lower() not in leftvalue.lower()
        elif operator == "~":
            if isinstance(leftvalue, list):
                return any(map(lambda a: rightvalue.lower() in a.lower(), leftvalue))
            else:
                return rightvalue.lower() in leftvalue.lower()

    def __compute_not_operator(self, tokens):
        operator, value = tokens

        if operator == "not":
            return not value

        return value

    def __compute_formula(self, tokens):
        return self.__myreduce(tokens[0])

    def __myreduce(self, elements):
        first = elements[0]
        for i in range(1, len(elements), 2):
            if elements[i] == "and":
                first = (first and elements[i+1])
            elif elements[i] == "or":
                first = (first or elements[i+1])

        return first

    def __compute_statement_symbol(self, tokens):
        def add_statement_to_list(key, statement):
            list_statement = []

            if key in statement:
                if isinstance(statement[key], list):
                    for elem in statement[key]:
                        list_statement.append(elem)
                else:
                    list_statement.append(statement[key])

            return list_statement

        try:
            if tokens[0] == "Type":
                return [self.role['_type']]
            elif tokens[0] in ["Effective", "Name", "Arn", 'KeyId', "PolicyName", "Trusted"]:
                return [self.role[tokens[0]]]
            else:
                if isinstance(self.statement[tokens[0]], list):
                    return [self.statement[tokens[0]]]
                else:
                    return [[self.statement[tokens[0]]]]
        except TypeError:
            return [""]
        except KeyError:
            return [""]

    def is_visible(self, role, statement):
        self.role = role
        self.statement = statement
        try:
            return self.finalformula.parseString(self.filter_string, parseAll=True)[0]
        except ParseException:
            raise Exception("Incorrect language expression")
