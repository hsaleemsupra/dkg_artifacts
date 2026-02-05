from json import load

from utilities.utils import PathMaker


class FaultyNodeIdentifier:
    def __init__(self, json):
        self.faulty_identy = list()
        for identity in json:
            node_key = PathMaker.node_key_file(identity["tribe"], identity["clan"], identity["position"])
            self.faulty_identy.append(node_key)

    @staticmethod
    def load(filename):
        assert isinstance(filename, str)
        with open(filename, 'r') as f:
            data = load(f)
            return FaultyNodeIdentifier(data)
