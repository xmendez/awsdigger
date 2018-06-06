from .session import Session

def dig(**kwargs):
    return Session(**kwargs).dig()
